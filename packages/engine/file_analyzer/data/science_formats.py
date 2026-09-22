"""Dependency-free header/metadata parsers for scientific & imaging containers.

These readers extract *structural metadata only* (dimensions, dtype, geo-referencing,
bounding boxes, record counts) by parsing file headers directly with the standard
library.  They never decode pixel/point payloads and never require GDAL, pydicom,
nibabel, rawpy, laspy or open3d to be installed -- an accelerator library is used by
the calling handler only when it happens to be present.

Every public ``read_*`` returns a plain ``dict`` of metadata, or raises on a byte
signature it does not recognise.  Privacy note: the DICOM reader deliberately reads
*only* technical acquisition tags and never touches the patient (0010) group or the
PixelData (7FE0,0010) element.
"""

from __future__ import annotations

import gzip
import struct
from typing import Any, Dict, List, Tuple

__all__ = [
    "read_tiff",
    "read_geotiff_extras",
    "read_camera_raw",
    "read_esri_ascii_grid",
    "read_vrt",
    "read_netcdf_classic",
    "read_dicom",
    "read_nifti",
    "read_nrrd",
    "read_mgh",
    "read_pcd",
    "read_las",
    "read_e57",
    "read_caf",
    "read_ogg",
    "read_wavpack",
    "read_tta",
    "read_ape",
]


# ======================================================================
# little helpers
# ======================================================================
def _open_head(path, n: int) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def _maybe_gunzip_head(path, n: int) -> bytes:
    """Read ``n`` bytes, transparently gunzipping when the file is gzip-framed."""
    raw = _open_head(path, 2)
    if raw[:2] == b"\x1f\x8b":
        with gzip.open(path, "rb") as f:
            return f.read(n)
    with open(path, "rb") as f:
        return f.read(n)


# ======================================================================
# TIFF / GeoTIFF / DNG-family (shared IFD reader)
# ======================================================================
# TIFF field type -> (byte size, struct code)
_TIFF_TYPE = {
    1: (1, "B"),
    2: (1, "c"),
    3: (2, "H"),
    4: (4, "I"),
    5: (8, "II"),
    6: (1, "b"),
    7: (1, "B"),
    8: (2, "h"),
    9: (4, "i"),
    10: (8, "ii"),
    11: (4, "f"),
    12: (8, "d"),
    13: (4, "I"),
    16: (8, "Q"),
    17: (8, "q"),
    18: (8, "Q"),
}
# tag numbers we care about
_T_IMAGEWIDTH = 256
_T_IMAGELENGTH = 257
_T_BITSPERSAMPLE = 258
_T_COMPRESSION = 259
_T_PHOTOMETRIC = 262
_T_MAKE = 271
_T_MODEL = 272
_T_SAMPLESPERPIXEL = 277
_T_SOFTWARE = 305
_T_DATETIME = 306
_T_SAMPLEFORMAT = 339
_T_TILEWIDTH = 322
_T_TILELENGTH = 323
_T_MODELPIXELSCALE = 33550
_T_MODELTIEPOINT = 33922
_T_MODELTRANSFORM = 34264
_T_GEOKEYDIR = 34735
_T_GEODOUBLE = 34736
_T_GEOASCII = 34737
_T_GDAL_METADATA = 42112
_T_GDAL_NODATA = 42113
_T_DNGVERSION = 50706
_T_UNIQUECAMERAMODEL = 50708
_T_CFAPATTERNDIM = 33421
_T_EXIFIFD = 34665

# accepted "magic" second-word values (42=TIFF, 43=BigTIFF, 0x55=Panasonic RW2,
# 'RO'/'SR' = Olympus ORF variants)
_TIFF_MAGICS = {42, 43, 0x55, 0x4F52, 0x5352}

_COMPRESSION_NAMES = {
    1: "none",
    2: "ccitt_rle",
    3: "ccitt_g3",
    4: "ccitt_g4",
    5: "lzw",
    6: "jpeg_old",
    7: "jpeg",
    8: "deflate",
    32773: "packbits",
    32946: "deflate",
    34712: "jpeg2000",
    34892: "dng_lossy",
    7794: "dng_lossless_prev",
}
_PHOTOMETRIC_NAMES = {
    0: "white_is_zero",
    1: "black_is_zero",
    2: "rgb",
    3: "palette",
    5: "cmyk",
    6: "ycbcr",
    8: "cielab",
    32803: "cfa",
    34892: "linear_raw",
}


class _TiffReader:
    def __init__(self, fh):
        self.fh = fh
        head = fh.read(8)
        if head[:2] == b"II":
            self.bo = "<"
        elif head[:2] == b"MM":
            self.bo = ">"
        else:
            raise ValueError("not a TIFF byte-order mark")
        magic = struct.unpack(self.bo + "H", head[2:4])[0]
        if magic not in _TIFF_MAGICS:
            raise ValueError("not a TIFF-family magic (%d)" % magic)
        self.bigtiff = magic == 43
        if self.bigtiff:
            # BigTIFF: bytesize(2)=8, reserved(2)=0, first IFD offset(8)
            fh.seek(8)
            self.first_ifd = struct.unpack(self.bo + "Q", fh.read(8))[0]
            self._off_fmt = "Q"
            self._off_size = 8
        else:
            self.first_ifd = struct.unpack(self.bo + "I", head[4:8])[0]
            self._off_fmt = "I"
            self._off_size = 4

    def _u(self, fmt, data):
        return struct.unpack(self.bo + fmt, data)

    def read_ifd(self, offset: int) -> Dict[int, Tuple[int, int, bytes, int]]:
        """Return {tag: (type, count, value_field_bytes, value_or_offset)}."""
        fh = self.fh
        fh.seek(offset)
        if self.bigtiff:
            count = self._u("Q", fh.read(8))[0]
            entry_size, count_fmt, val_fld = 20, "Q", 8
        else:
            count = self._u("H", fh.read(2))[0]
            entry_size, count_fmt, val_fld = 12, "I", 4
        entries: Dict[int, Tuple[int, int, bytes, int]] = {}
        blob = fh.read(entry_size * count)
        for k in range(count):
            e = blob[k * entry_size : (k + 1) * entry_size]
            if len(e) < entry_size:
                break
            tag, typ = self._u("HH", e[0:4])
            cnt = self._u(count_fmt, e[4 : 4 + (8 if self.bigtiff else 4)])[0]
            valbytes = e[4 + (8 if self.bigtiff else 4) :]
            entries[tag] = (typ, cnt, valbytes, val_fld)
        return entries

    def value(self, entry) -> List[Any]:
        typ, cnt, valbytes, val_fld = entry
        if typ not in _TIFF_TYPE:
            return []
        tsize, code = _TIFF_TYPE[typ]
        total = tsize * cnt
        if total <= val_fld:
            data = valbytes[:total]
        else:
            off = self._u(self._off_fmt, valbytes[: self._off_size])[0]
            self.fh.seek(off)
            data = self.fh.read(total)
        if typ == 2:  # ASCII
            return [data.split(b"\x00", 1)[0].decode("latin-1", "replace")]
        if typ in (5, 10):  # RATIONAL / SRATIONAL -> float pairs
            out = []
            c2 = "II" if typ == 5 else "ii"
            for j in range(cnt):
                num, den = self._u(c2, data[j * 8 : j * 8 + 8])
                out.append(num / den if den else 0.0)
            return out
        out = []
        for j in range(cnt):
            chunk = data[j * tsize : (j + 1) * tsize]
            if len(chunk) < tsize:
                break
            out.append(self._u(code, chunk)[0])
        return out


def _read_tiff_ifd0(path) -> Tuple["_TiffReader", Dict[int, Any]]:
    fh = open(path, "rb")
    try:
        tr = _TiffReader(fh)
        entries = tr.read_ifd(tr.first_ifd)
    except Exception:
        fh.close()
        raise
    return tr, entries


def read_tiff(path) -> Dict[str, Any]:
    """Structural metadata from TIFF-IFD0 (dimensions, bit depth, compression)."""
    tr, ent = _read_tiff_ifd0(path)
    try:

        def one(tag):
            return tr.value(ent[tag])[0] if tag in ent else None

        def many(tag):
            return tr.value(ent[tag]) if tag in ent else None

        out: Dict[str, Any] = {
            "byte_order": "little" if tr.bo == "<" else "big",
            "bigtiff": tr.bigtiff,
            "width": one(_T_IMAGEWIDTH),
            "height": one(_T_IMAGELENGTH),
            "samples_per_pixel": one(_T_SAMPLESPERPIXEL),
            "bits_per_sample": many(_T_BITSPERSAMPLE),
            "tile_width": one(_T_TILEWIDTH),
            "tile_length": one(_T_TILELENGTH),
        }
        comp = one(_T_COMPRESSION)
        if comp is not None:
            out["compression"] = _COMPRESSION_NAMES.get(comp, str(comp))
        photo = one(_T_PHOTOMETRIC)
        if photo is not None:
            out["photometric"] = _PHOTOMETRIC_NAMES.get(photo, str(photo))
        for tag, key in (
            (_T_MAKE, "make"),
            (_T_MODEL, "model"),
            (_T_SOFTWARE, "software"),
            (_T_DATETIME, "datetime"),
            (_T_UNIQUECAMERAMODEL, "unique_camera_model"),
        ):
            v = one(tag)
            if v:
                out[key] = str(v).strip()[:128]
        if _T_DNGVERSION in ent:
            ver = tr.value(ent[_T_DNGVERSION])
            out["dng_version"] = ".".join(str(x) for x in ver[:4])
        out["has_geokeys"] = _T_GEOKEYDIR in ent
        out["is_cfa"] = (photo in (32803,)) or (_T_CFAPATTERNDIM in ent)
        return {k: v for k, v in out.items() if v is not None}
    finally:
        tr.fh.close()


# GeoTIFF geokey IDs
_GK_MODELTYPE = 1024
_GK_RASTERTYPE = 1025
_GK_GEOGCS = 2048
_GK_PROJCS = 3072
_GK_GEOGANGULARUNITS = 2054
_MODELTYPE_NAMES = {1: "projected", 2: "geographic", 3: "geocentric"}


def read_geotiff_extras(path) -> Dict[str, Any]:
    """GeoTIFF geo-referencing: CRS (EPSG), pixel scale, tiepoint, origin/bbox.

    Raises when the TIFF carries no GeoKeyDirectory tag (i.e. plain raster TIFF).
    """
    tr, ent = _read_tiff_ifd0(path)
    try:
        if _T_GEOKEYDIR not in ent:
            raise ValueError("no GeoKeyDirectory (not a GeoTIFF)")
        keys = tr.value(ent[_T_GEOKEYDIR])
        out: Dict[str, Any] = {}
        if len(keys) >= 4:
            nkeys = keys[3]
            geokeys: Dict[int, int] = {}
            for i in range(nkeys):
                base = 4 + i * 4
                if base + 3 >= len(keys):
                    break
                key_id, loc, count, val = keys[base : base + 4]
                if loc == 0:  # value stored inline in the directory
                    geokeys[key_id] = val
            mt = geokeys.get(_GK_MODELTYPE)
            if mt is not None:
                out["model_type"] = _MODELTYPE_NAMES.get(mt, str(mt))
            proj = geokeys.get(_GK_PROJCS)
            geog = geokeys.get(_GK_GEOGCS)
            if proj and proj not in (0, 32767):
                out["epsg"] = proj
                out["crs"] = "EPSG:%d" % proj
            elif geog and geog not in (0, 32767):
                out["epsg"] = geog
                out["crs"] = "EPSG:%d" % geog
        scale = tr.value(ent[_T_MODELPIXELSCALE]) if _T_MODELPIXELSCALE in ent else None
        tie = tr.value(ent[_T_MODELTIEPOINT]) if _T_MODELTIEPOINT in ent else None
        if scale and len(scale) >= 2:
            out["pixel_scale"] = [scale[0], scale[1]]
        if tie and len(tie) >= 6:
            out["origin"] = [tie[3], tie[4]]
        w = tr.value(ent[_T_IMAGEWIDTH])[0] if _T_IMAGEWIDTH in ent else None
        h = tr.value(ent[_T_IMAGELENGTH])[0] if _T_IMAGELENGTH in ent else None
        if scale and tie and w and h and len(scale) >= 2 and len(tie) >= 6:
            ox, oy = tie[3], tie[4]
            sx, sy = scale[0], scale[1]
            minx, maxx = ox, ox + sx * w
            maxy, miny = oy, oy - sy * h
            out["bbox"] = [minx, min(miny, maxy), maxx, max(miny, maxy)]
        if _T_GDAL_NODATA in ent:
            nd = tr.value(ent[_T_GDAL_NODATA])
            if nd:
                out["nodata"] = str(nd[0]).strip()
        return out
    finally:
        tr.fh.close()


# camera-raw specific: RAF / CR3 / X3F
def read_camera_raw(path, ext: str) -> Dict[str, Any]:
    """Camera-raw metadata. TIFF-based raws (CR2/NEF/ARW/DNG/ORF/RW2/PEF/...) go
    through the shared IFD reader; Fujifilm RAF, Canon CR3 (ISO-BMFF) and Sigma
    X3F have their own container magics handled here."""
    head = _open_head(path, 64)
    # Fujifilm RAF
    if head[:15] == b"FUJIFILMCCD-RAW":
        model = head[28:60].split(b"\x00", 1)[0].decode("latin-1", "replace").strip()
        return {
            "container": "raf",
            "make": "FUJIFILM",
            "model": model or None,
            "raw_version": head[15:19].decode("latin-1", "replace").strip(),
        }
    # Sigma / Foveon X3F
    if head[:4] == b"FOVb":
        ver_minor, ver_major = struct.unpack("<HH", head[4:8])
        return {
            "container": "x3f",
            "make": "SIGMA",
            "x3f_version": "%d.%d" % (ver_major, ver_minor),
        }
    # Canon CR3 / other ISO-BMFF: first box must be 'ftyp'
    if head[4:8] == b"ftyp":
        brand = head[8:12].decode("latin-1", "replace").strip()
        out = {"container": "iso_bmff", "major_brand": brand}
        if brand.startswith("crx"):
            out["make"] = "CANON"
            out["format"] = "cr3"
        return out
    # everything else: assume TIFF-based raw
    info = read_tiff(path)
    info.setdefault("container", "tiff")
    return info


# ======================================================================
# ESRI ASCII grid / GDAL VRT / NetCDF-classic
# ======================================================================
def read_esri_ascii_grid(path) -> Dict[str, Any]:
    """ESRI/Arc ASCII grid (.asc/.grd): ncols/nrows/xllcorner/cellsize/NODATA."""
    hdr: Dict[str, str] = {}
    with open(path, "r", encoding="latin-1", errors="replace") as f:
        for _ in range(12):
            pos = f.tell()
            line = f.readline()
            if not line:
                break
            parts = line.split()
            if len(parts) == 2 and parts[0].lower() in (
                "ncols",
                "nrows",
                "xllcorner",
                "yllcorner",
                "xllcenter",
                "yllcenter",
                "cellsize",
                "nodata_value",
                "dx",
                "dy",
            ):
                hdr[parts[0].lower()] = parts[1]
            else:
                f.seek(pos)
                break
    if "ncols" not in hdr or "nrows" not in hdr:
        raise ValueError("not an ESRI ASCII grid (missing ncols/nrows)")
    out: Dict[str, Any] = {
        "driver": "esri_ascii_grid",
        "width": int(float(hdr["ncols"])),
        "height": int(float(hdr["nrows"])),
    }
    cs = hdr.get("cellsize")
    if cs:
        out["cellsize"] = float(cs)
    if "nodata_value" in hdr:
        out["nodata"] = hdr["nodata_value"]
    x0 = hdr.get("xllcorner", hdr.get("xllcenter"))
    y0 = hdr.get("yllcorner", hdr.get("yllcenter"))
    if x0 and y0 and cs:
        x0f, y0f, csf = float(x0), float(y0), float(cs)
        out["bbox"] = [x0f, y0f, x0f + csf * out["width"], y0f + csf * out["height"]]
    return out


def read_vrt(path) -> Dict[str, Any]:
    """GDAL .vrt XML virtual raster: raster size, band count, SRS, geotransform."""
    import re
    import xml.etree.ElementTree as ET

    tree = ET.parse(path)
    root = tree.getroot()
    if root.tag != "VRTDataset":
        raise ValueError("not a GDAL VRTDataset")
    out: Dict[str, Any] = {"driver": "vrt"}
    for a in ("rasterXSize", "rasterYSize"):
        if root.get(a):
            out["width" if a == "rasterXSize" else "height"] = int(root.get(a))
    bands = root.findall("VRTRasterBand")
    out["band_count"] = len(bands)
    if bands:
        dt = bands[0].get("dataType")
        if dt:
            out["data_type"] = dt
    srs = root.find("SRS")
    if srs is not None and srs.text:
        m = re.search(r'AUTHORITY\["EPSG","(\d+)"\]', srs.text)
        if m:
            out["epsg"] = int(m.group(1))
            out["crs"] = "EPSG:" + m.group(1)
        elif srs.text.strip():
            out["crs"] = srs.text.strip()[:120]
    gt = root.find("GeoTransform")
    if gt is not None and gt.text:
        try:
            vals = [float(x) for x in gt.text.replace(",", " ").split()]
            if len(vals) == 6 and out.get("width") and out.get("height"):
                ox, px, _, oy, _, py = vals
                w, h = out["width"], out["height"]
                out["origin"] = [ox, oy]
                out["pixel_scale"] = [px, abs(py)]
                xs = [ox, ox + px * w]
                ys = [oy, oy + py * h]
                out["bbox"] = [min(xs), min(ys), max(xs), max(ys)]
        except ValueError:
            pass
    return out


_NC_TYPE = {
    1: ("i1", 1),
    2: ("char", 1),
    3: ("i2", 2),
    4: ("i4", 4),
    5: ("f4", 4),
    6: ("f8", 8),
}


def read_netcdf_classic(path) -> Dict[str, Any]:
    """NetCDF classic/64-bit-offset (magic 'CDF\\x01'/'\\x02'/'\\x05'): dims + vars."""
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic[:3] != b"CDF" or magic[3] not in (1, 2, 5):
            raise ValueError("not a classic NetCDF file")
        version = magic[3]
        offbytes = 8 if version == 2 else 4
        off_fmt = ">Q" if version == 2 else ">I"

        def u32():
            return struct.unpack(">I", f.read(4))[0]

        def offv():
            return struct.unpack(off_fmt, f.read(offbytes))[0]

        def name():
            n = u32()
            s = f.read(n)
            pad = (4 - (n % 4)) % 4
            f.read(pad)
            return s.decode("latin-1", "replace")

        _numrecs = u32()  # STREAMING or fixed record count
        NC_DIMENSION, NC_VARIABLE, NC_ATTRIBUTE = 0x0A, 0x0B, 0x0C
        dims: List[Tuple[str, int]] = []
        tag = u32()
        ndims = u32()
        if tag == NC_DIMENSION:
            for _ in range(ndims):
                dn = name()
                dlen = u32()
                dims.append((dn, dlen))
        else:
            ndims = 0

        def skip_attrs():
            atag = u32()
            natts = u32()
            if atag == NC_ATTRIBUTE:
                for _ in range(natts):
                    name()
                    nc_type = u32()
                    nelems = u32()
                    tsize = _NC_TYPE.get(nc_type, ("?", 1))[1]
                    total = tsize * nelems
                    f.read(total + ((4 - (total % 4)) % 4))

        skip_attrs()  # global attributes
        vtag = u32()
        nvars = u32()
        variables: List[Dict[str, Any]] = []
        if vtag == NC_VARIABLE:
            for _ in range(nvars):
                vn = name()
                vndims = u32()
                dimids = [u32() for _ in range(vndims)]
                skip_attrs()
                nc_type = u32()
                _vsize = u32()
                _begin = offv()
                shape = [dims[d][1] for d in dimids if d < len(dims)]
                variables.append(
                    {
                        "name": vn,
                        "dtype": _NC_TYPE.get(nc_type, ("?", 0))[0],
                        "shape": shape,
                        "dims": [dims[d][0] for d in dimids if d < len(dims)],
                    }
                )
    return {
        "driver": "netcdf_classic",
        "version": version,
        "dimensions": [{"name": n, "size": s} for n, s in dims],
        "dimension_count": len(dims),
        "variables": variables,
        "variable_count": len(variables),
    }


# ======================================================================
# Medical imaging: DICOM / NIfTI / NRRD / MGH
# ======================================================================
# implicit-VR value representations for the technical tags we surface
_DICOM_US_TAGS = {
    (0x0028, 0x0002),
    (0x0028, 0x0010),
    (0x0028, 0x0011),
    (0x0028, 0x0100),
    (0x0028, 0x0101),
    (0x0028, 0x0102),
    (0x0028, 0x0103),
    (0x0028, 0x0006),
}
_DICOM_STR_TAGS = {
    (0x0002, 0x0010): "transfer_syntax_uid",
    (0x0002, 0x0002): "media_storage_sop_class_uid",
    (0x0008, 0x0016): "sop_class_uid",
    (0x0008, 0x0060): "modality",
    (0x0008, 0x0070): "manufacturer",
    (0x0008, 0x1090): "manufacturer_model",
    (0x0008, 0x103E): "series_description",
    (0x0018, 0x0050): "slice_thickness",
    (0x0018, 0x0060): "kvp",
    (0x0018, 0x0088): "spacing_between_slices",
    (0x0028, 0x0004): "photometric_interpretation",
    (0x0028, 0x0008): "number_of_frames",
    (0x0028, 0x0030): "pixel_spacing",
    (0x0028, 0x1050): "window_center",
    (0x0028, 0x1051): "window_width",
}
_DICOM_US_NAMES = {
    (0x0028, 0x0002): "samples_per_pixel",
    (0x0028, 0x0010): "rows",
    (0x0028, 0x0011): "columns",
    (0x0028, 0x0100): "bits_allocated",
    (0x0028, 0x0101): "bits_stored",
    (0x0028, 0x0102): "high_bit",
    (0x0028, 0x0103): "pixel_representation",
    (0x0028, 0x0006): "planar_configuration",
}
# VRs whose length is encoded as a 4-byte field (explicit VR)
_DICOM_VR_LONG = {
    b"OB",
    b"OW",
    b"OF",
    b"SQ",
    b"UT",
    b"UN",
    b"UC",
    b"UR",
    b"OD",
    b"OL",
    b"OV",
    b"UI",
}
# NB: UI actually uses a 2-byte length; it is NOT in the long set below.
_DICOM_VR_LONG.discard(b"UI")
_PIXEL_DATA = (0x7FE0, 0x0010)


def read_dicom(path) -> Dict[str, Any]:
    """Parse DICOM *technical* tags only (privacy-safe: the patient 0010 group
    and PixelData are never read).  Handles preamble/no-preamble and both
    implicit- and explicit-VR little/big endian transfer syntaxes."""
    with open(path, "rb") as f:
        preamble = f.read(132)
        if preamble[128:132] == b"DICM":
            start = 132
        else:
            # some files omit the 128-byte preamble; require a plausible group tag
            g = struct.unpack("<H", preamble[0:2])[0]
            if g not in (0x0002, 0x0008):
                raise ValueError("not a DICOM stream")
            start = 0
        f.seek(0, 2)
        fsize = f.tell()
        f.seek(start)
        out: Dict[str, Any] = {}
        explicit = True  # meta group (0002) is always explicit VR LE
        bo = "<"
        cap = min(fsize, start + 8 * 1024 * 1024)
        switched = False
        while f.tell() < cap:
            pos = f.tell()
            tag_raw = f.read(4)
            if len(tag_raw) < 4:
                break
            group, elem = struct.unpack(bo + "HH", tag_raw)
            if (group, elem) == _PIXEL_DATA or group >= 0x7FE0:
                break  # never read pixel data
            # switch transfer syntax once we leave the file-meta (0002) group
            if not switched and group != 0x0002:
                ts = out.get("transfer_syntax_uid", "")
                if ts == "1.2.840.10008.1.2":
                    explicit = False
                elif ts == "1.2.840.10008.1.2.2":
                    explicit, bo = True, ">"
                else:
                    explicit = True
                switched = True
            if explicit:
                vr = f.read(2)
                if vr in _DICOM_VR_LONG:
                    f.read(2)  # reserved
                    length = struct.unpack(bo + "I", f.read(4))[0]
                else:
                    length = struct.unpack(bo + "H", f.read(2))[0]
            else:
                vr = None
                length = struct.unpack(bo + "I", f.read(4))[0]
            if length == 0xFFFFFFFF:  # undefined length (SQ) -> stop, avoid PII depth
                break
            # skip the patient identity group entirely without reading its values
            if group == 0x0010:
                f.seek(length, 1)
                continue
            key = (group, elem)
            want_str = key in _DICOM_STR_TAGS
            want_us = key in _DICOM_US_NAMES
            if want_str or want_us:
                val = f.read(length)
                if want_us and len(val) >= 2:
                    out[_DICOM_US_NAMES[key]] = struct.unpack(bo + "H", val[:2])[0]
                elif want_str:
                    out[_DICOM_STR_TAGS[key]] = val.decode("latin-1", "replace").strip(
                        " \x00"
                    )
            else:
                f.seek(length, 1)
        # normalise a couple of numeric strings
        for k in ("number_of_frames",):
            if k in out:
                try:
                    out[k] = int(str(out[k]).strip())
                except ValueError:
                    pass
        if not out:
            raise ValueError("no technical DICOM tags recovered")
        out["parser"] = "stdlib_dicom"
        return out


_NIFTI_DTYPE = {
    0: "unknown",
    1: "bool",
    2: "uint8",
    4: "int16",
    8: "int32",
    16: "float32",
    32: "complex64",
    64: "float64",
    128: "rgb24",
    256: "int8",
    512: "uint16",
    768: "uint32",
    1024: "int64",
    1280: "uint64",
    1536: "float128",
    1792: "complex128",
    2048: "complex256",
    2304: "rgba32",
}


def read_nifti(path) -> Dict[str, Any]:
    """NIfTI-1/-2 header (.nii, transparently .nii.gz): shape, dtype, voxel sizes."""
    raw = _maybe_gunzip_head(path, 544)
    if len(raw) < 4:
        raise ValueError("file too small for NIfTI")
    # NIfTI-1 sizeof_hdr==348; NIfTI-2 sizeof_hdr==540. detect endian + version.
    for bo in ("<", ">"):
        sz = struct.unpack(bo + "i", raw[0:4])[0]
        if sz == 348:
            return _nifti1(raw, bo)
        if sz == 540:
            return _nifti2(raw, bo)
    raise ValueError("not a NIfTI header (bad sizeof_hdr)")


def _nifti1(raw: bytes, bo: str) -> Dict[str, Any]:
    dim = struct.unpack(bo + "8h", raw[40:56])
    datatype = struct.unpack(bo + "h", raw[70:72])[0]
    bitpix = struct.unpack(bo + "h", raw[72:74])[0]
    pixdim = struct.unpack(bo + "8f", raw[76:108])
    ndim = dim[0]
    shape = list(dim[1 : 1 + ndim]) if 0 < ndim <= 7 else list(dim[1:])
    voxel = [round(v, 6) for v in pixdim[1 : 1 + ndim]] if 0 < ndim <= 7 else []
    magic = raw[344:348]
    return {
        "format": "nifti1",
        "byte_order": "little" if bo == "<" else "big",
        "magic": magic.decode("latin-1", "replace").strip("\x00"),
        "ndim": ndim,
        "shape": shape,
        "dtype": _NIFTI_DTYPE.get(datatype, str(datatype)),
        "bitpix": bitpix,
        "voxel_sizes": voxel,
    }


def _nifti2(raw: bytes, bo: str) -> Dict[str, Any]:
    magic = raw[4:12]
    datatype = struct.unpack(bo + "h", raw[12:14])[0]
    bitpix = struct.unpack(bo + "h", raw[14:16])[0]
    dim = struct.unpack(bo + "8q", raw[16:80])
    pixdim = struct.unpack(bo + "8d", raw[104:168])
    ndim = dim[0]
    shape = list(dim[1 : 1 + ndim]) if 0 < ndim <= 7 else list(dim[1:])
    voxel = [round(v, 6) for v in pixdim[1 : 1 + ndim]] if 0 < ndim <= 7 else []
    return {
        "format": "nifti2",
        "byte_order": "little" if bo == "<" else "big",
        "magic": magic.decode("latin-1", "replace").strip("\x00"),
        "ndim": ndim,
        "shape": shape,
        "dtype": _NIFTI_DTYPE.get(datatype, str(datatype)),
        "bitpix": bitpix,
        "voxel_sizes": voxel,
    }


def read_nrrd(path) -> Dict[str, Any]:
    """NRRD (.nrrd/.nhdr) text header: type, dimension, sizes, encoding, space."""
    fields: Dict[str, str] = {}
    with open(path, "rb") as f:
        first = f.readline()
        if not first.startswith(b"NRRD"):
            raise ValueError("not an NRRD file")
        version = first.strip().decode("latin-1", "replace")
        for _ in range(200):
            line = f.readline()
            if not line or line.strip() == b"":
                break  # blank line ends the header
            if line.startswith(b"#"):
                continue
            txt = line.decode("latin-1", "replace").rstrip("\n").rstrip("\r")
            if ":=" in txt:
                k, v = txt.split(":=", 1)
                fields["kv:" + k.strip()] = v.strip()
            elif ":" in txt:
                k, v = txt.split(":", 1)
                fields[k.strip().lower()] = v.strip()
    out: Dict[str, Any] = {"format": "nrrd", "nrrd_version": version}
    if "type" in fields:
        out["dtype"] = fields["type"]
    if "dimension" in fields:
        try:
            out["ndim"] = int(fields["dimension"])
        except ValueError:
            pass
    if "sizes" in fields:
        try:
            out["shape"] = [int(x) for x in fields["sizes"].split()]
        except ValueError:
            pass
    for k in ("encoding", "endian", "space"):
        if k in fields:
            out[k] = fields[k]
    if "space dimension" in fields:
        out["space_dimension"] = fields["space dimension"]
    return out


_MGH_DTYPE = {0: "uint8", 1: "int32", 3: "float32", 4: "int16"}


def read_mgh(path) -> Dict[str, Any]:
    """FreeSurfer MGH/MGZ volume header (big-endian, .mgz gunzipped): shape+dtype."""
    raw = _maybe_gunzip_head(path, 284)
    if len(raw) < 28:
        raise ValueError("file too small for MGH")
    version, width, height, depth, nframes, mtype, dof = struct.unpack(
        ">iiiiiii", raw[0:28]
    )
    if version != 1:
        raise ValueError("unexpected MGH version %d" % version)
    out = {
        "format": "mgh",
        "shape": [width, height, depth],
        "nframes": nframes,
        "dtype": _MGH_DTYPE.get(mtype, str(mtype)),
        "degrees_of_freedom": dof,
    }
    good_ras = struct.unpack(">h", raw[28:30])[0]
    if good_ras == 1 and len(raw) >= 42:
        xs, ys, zs = struct.unpack(">fff", raw[30:42])
        out["voxel_sizes"] = [round(xs, 6), round(ys, 6), round(zs, 6)]
    return out


# ======================================================================
# Point clouds: PCD / LAS(LAZ) / E57
# ======================================================================
def read_pcd(path) -> Dict[str, Any]:
    """PCL PCD header (ascii/binary/binary_compressed): fields, point count, size."""
    hdr: Dict[str, str] = {}
    fields: List[str] = []
    with open(path, "rb") as f:
        for _ in range(64):
            line = f.readline()
            if not line:
                break
            txt = line.decode("latin-1", "replace").strip()
            if not txt or txt.startswith("#"):
                continue
            parts = txt.split()
            key = parts[0].upper()
            if key == "FIELDS":
                fields = parts[1:]
            elif key in (
                "VERSION",
                "SIZE",
                "TYPE",
                "COUNT",
                "WIDTH",
                "HEIGHT",
                "POINTS",
                "DATA",
                "VIEWPOINT",
            ):
                hdr[key] = " ".join(parts[1:])
            if key == "DATA":
                break
    if not fields and "WIDTH" not in hdr:
        raise ValueError("not a PCD header")
    out: Dict[str, Any] = {
        "format": "pcd",
        "fields": fields,
        "field_count": len(fields),
    }
    if "VERSION" in hdr:
        out["pcd_version"] = hdr["VERSION"]
    if "DATA" in hdr:
        out["encoding"] = hdr["DATA"]
    width = int(hdr["WIDTH"]) if hdr.get("WIDTH", "").isdigit() else None
    height = int(hdr["HEIGHT"]) if hdr.get("HEIGHT", "").isdigit() else None
    if hdr.get("POINTS", "").isdigit():
        out["point_count"] = int(hdr["POINTS"])
    elif width is not None and height is not None:
        out["point_count"] = width * height
    if width is not None:
        out["width"] = width
    if height is not None:
        out["height"] = height
    if "TYPE" in hdr and "SIZE" in hdr:
        out["field_types"] = hdr["TYPE"].split()
        out["field_sizes"] = hdr["SIZE"].split()
    return out


def read_las(path) -> Dict[str, Any]:
    """ASPRS LAS/LAZ public header block: version, point count, format, bbox, CRS."""
    with open(path, "rb") as f:
        head = f.read(375)
    if head[:4] != b"LASF":
        raise ValueError("not a LAS/LAZ file")
    ver_major, ver_minor = head[24], head[25]
    header_size = struct.unpack("<H", head[94:96])[0]
    point_format = head[104]
    point_len = struct.unpack("<H", head[105:107])[0]
    legacy_count = struct.unpack("<I", head[107:111])[0]
    scale = struct.unpack("<3d", head[131:155])
    offset = struct.unpack("<3d", head[155:179])
    maxx, minx, maxy, miny, maxz, minz = struct.unpack("<6d", head[179:227])
    compressed = bool(point_format & 0x80)
    fmt_id = point_format & 0x3F
    count = legacy_count
    if ver_major == 1 and ver_minor >= 4 and len(head) >= 255:
        big = struct.unpack("<Q", head[247:255])[0]
        if big:
            count = big
    return {
        "format": "laz" if compressed else "las",
        "las_version": "%d.%d" % (ver_major, ver_minor),
        "point_format": fmt_id,
        "point_record_length": point_len,
        "point_count": count,
        "compressed": compressed,
        "scale": [scale[0], scale[1], scale[2]],
        "offset": [offset[0], offset[1], offset[2]],
        "bbox": [minx, miny, minz, maxx, maxy, maxz],
        "header_size": header_size,
    }


def read_e57(path) -> Dict[str, Any]:
    """ASTM E57 point cloud: header + XML footer scan for scan/record counts."""
    import re

    with open(path, "rb") as f:
        head = f.read(48)
        if head[:8] != b"ASTM-E57":
            raise ValueError("not an E57 file")
        ver_major, ver_minor = struct.unpack("<II", head[8:16])
        _phys_len, xml_offset, xml_len = struct.unpack("<QQQ", head[16:40])
        f.seek(xml_offset)
        blob = f.read(min(xml_len + 4096, 16 * 1024 * 1024))
    text = blob.decode("latin-1", "replace")
    lo = text.find("<?xml")
    if lo > 0:
        text = text[lo:]
    counts = [int(m) for m in re.findall(r'recordCount"[^>]*>\s*(\d+)', text)]
    if not counts:
        counts = [int(m) for m in re.findall(r"<recordCount>\s*(\d+)", text)]
    scans = text.count("<vectorChild")
    out: Dict[str, Any] = {
        "format": "e57",
        "e57_version": "%d.%d" % (ver_major, ver_minor),
    }
    if scans:
        out["scan_count"] = scans
    if counts:
        out["point_count"] = sum(counts)
        out["per_scan_record_counts"] = counts[:64]
    guid = re.search(r"<guid[^>]*>([^<]+)</guid>", text)
    if guid:
        out["guid"] = guid.group(1).strip()[:64]
    return out


# ======================================================================
# Exotic audio: CAF / Ogg (Vorbis/Opus/FLAC) / WavPack / TTA / APE
# ======================================================================
def read_caf(path) -> Dict[str, Any]:
    """Apple Core Audio Format ('caff'): sample rate, channels, bit depth, frames."""
    with open(path, "rb") as f:
        head = f.read(8)
        if head[:4] != b"caff":
            raise ValueError("not a CAF file")
        out: Dict[str, Any] = {"codec": "caf"}
        for _ in range(32):
            chdr = f.read(12)
            if len(chdr) < 12:
                break
            ctype = chdr[:4]
            csize = struct.unpack(">q", chdr[4:12])[0]
            if ctype == b"desc":
                # CAFAudioFormat: Float64 mSampleRate + 6x UInt32 = 32 bytes.
                body = f.read(32)
                sr = struct.unpack(">d", body[0:8])[0]
                fmt_id = body[8:12].decode("latin-1", "replace").strip()
                _flags, _bytes_per_packet, _frames_per_packet, channels, bits = (
                    struct.unpack(">IIIII", body[12:32])
                )
                out.update(
                    {
                        "sample_rate_hz": int(sr),
                        "channels": channels,
                        "bit_depth": bits or None,
                        "format_id": fmt_id,
                    }
                )
                remaining = csize - 32
                if remaining > 0:
                    f.seek(remaining, 1)
            elif ctype == b"pakt":
                body = f.read(min(csize, 24))
                if len(body) >= 16:
                    num_frames = struct.unpack(">q", body[8:16])[0]
                    out["frame_count"] = num_frames
                    if out.get("sample_rate_hz"):
                        out["duration_seconds"] = round(
                            num_frames / out["sample_rate_hz"], 4
                        )
                if csize - len(body) > 0:
                    f.seek(csize - len(body), 1)
            else:
                if csize < 0:
                    break
                f.seek(csize, 1)
        return out


def read_ogg(path) -> Dict[str, Any]:
    """Ogg container first-page codec probe (Vorbis / Opus / FLAC-in-Ogg)."""
    with open(path, "rb") as f:
        page = f.read(4096)
    if page[:4] != b"OggS":
        raise ValueError("not an Ogg stream")
    nsegs = page[26]
    seg_table = page[27 : 27 + nsegs]
    payload_start = 27 + nsegs
    payload = page[payload_start:]
    out: Dict[str, Any] = {"container": "ogg"}
    if payload[:7] == b"\x01vorbis":
        ch = payload[11]
        sr = struct.unpack("<I", payload[12:16])[0]
        out.update({"codec": "vorbis", "channels": ch, "sample_rate_hz": sr})
    elif payload[:8] == b"OpusHead":
        ch = payload[9]
        sr = struct.unpack("<I", payload[12:16])[0]
        out.update(
            {
                "codec": "opus",
                "channels": ch,
                "input_sample_rate_hz": sr,
                "sample_rate_hz": 48000,
            }
        )
    elif payload[:5] == b"\x7fFLAC":
        out["codec"] = "flac_in_ogg"
        si = payload.find(b"fLaC")
        if si != -1:
            info = payload[si + 8 : si + 8 + 34]
            if len(info) >= 18:
                out["sample_rate_hz"] = (
                    (info[10] << 12) | (info[11] << 4) | (info[12] >> 4)
                )
                out["channels"] = ((info[12] >> 1) & 0x07) + 1
    else:
        out["codec"] = "ogg_unknown"
    _ = seg_table
    return out


_WAVPACK_SR = [
    6000,
    8000,
    9600,
    11025,
    12000,
    16000,
    22050,
    24000,
    32000,
    44100,
    48000,
    64000,
    88200,
    96000,
    192000,
]


def read_wavpack(path) -> Dict[str, Any]:
    """WavPack ('wvpk') block header: total samples, sample rate, channels."""
    with open(path, "rb") as f:
        head = f.read(32)
    if head[:4] != b"wvpk":
        raise ValueError("not a WavPack file")
    total_samples = struct.unpack("<I", head[12:16])[0]
    flags = struct.unpack("<I", head[24:28])[0]
    sr_index = (flags >> 23) & 0x0F
    mono = bool(flags & 0x04)
    out: Dict[str, Any] = {
        "codec": "wavpack",
        "channels": 1 if mono else 2,
        "bytes_per_sample": ((flags & 0x03) + 1),
    }
    if sr_index < len(_WAVPACK_SR):
        sr = _WAVPACK_SR[sr_index]
        out["sample_rate_hz"] = sr
        if total_samples not in (0, 0xFFFFFFFF):
            out["frame_count"] = total_samples
            out["duration_seconds"] = round(total_samples / sr, 4) if sr else None
    return out


def read_tta(path) -> Dict[str, Any]:
    """True Audio ('TTA1') header: channels, bit depth, sample rate, length."""
    with open(path, "rb") as f:
        head = f.read(22)
    if head[:4] != b"TTA1":
        raise ValueError("not a TTA1 file")
    audio_format, channels, bits = struct.unpack("<HHH", head[4:10])
    sr, data_len = struct.unpack("<II", head[10:18])
    out = {
        "codec": "tta",
        "channels": channels,
        "bit_depth": bits,
        "sample_rate_hz": sr,
        "frame_count": data_len,
    }
    if sr:
        out["duration_seconds"] = round(data_len / sr, 4)
    return out


def read_ape(path) -> Dict[str, Any]:
    """Monkey's Audio ('MAC ') header (APE >= 3.98 descriptor+header layout)."""
    with open(path, "rb") as f:
        head = f.read(4)
        if head[:4] != b"MAC ":
            raise ValueError("not a Monkey's Audio file")
        ver = struct.unpack("<H", f.read(2))[0]
        out: Dict[str, Any] = {"codec": "ape", "ape_version": ver / 1000.0}
        if ver >= 3980:
            # APE_DESCRIPTOR is 52 bytes total; header follows immediately after
            f.seek(4)
            desc = f.read(52)
            hdr = f.read(24)
            if len(hdr) >= 24:
                _blocks_per_frame, _final_blocks = struct.unpack("<II", hdr[8:16])
                bits, channels, sr = struct.unpack("<HHI", hdr[16:24])
                total_frames = struct.unpack("<I", hdr[4:8])[0]
                out.update(
                    {"bit_depth": bits, "channels": channels, "sample_rate_hz": sr}
                )
                total_blocks = (
                    (_blocks_per_frame * (total_frames - 1) + _final_blocks)
                    if total_frames
                    else 0
                )
                if total_blocks and sr:
                    out["frame_count"] = total_blocks
                    out["duration_seconds"] = round(total_blocks / sr, 4)
            _ = desc
        else:
            # legacy APE (<3.98): compact header right after 'MAC '+version
            f.seek(6)
            old = f.read(26)
            if len(old) >= 18:
                channels, sr = struct.unpack("<HI", old[8:14])
                out.update({"channels": channels, "sample_rate_hz": sr})
        return out
