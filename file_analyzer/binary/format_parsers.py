"""
Deep per-format binary parsers for the non-executable binary universe.

``MachineCodeAnalyzer`` (``machine_code.py``) owns the executable / object /
bytecode families (ELF, PE, Mach-O, ``.class``, ``.pyc``, WASM, DEX, ``ar``,
LLVM, UF2, OLE). This module supplies the *other* structural binary formats --
the ~1100 container / media / image / model / disk-image / firmware / scientific
/ serialization extensions that are neither source code, schema, database,
archive nor semantic data -- with genuine struct-level readers.

Design
------
Parsing is **magic-driven first**. ``BinaryFormatParser.analyze(path)`` reads a
bounded header window, identifies the concrete structural family from a curated
magic-signature table (this is real content detection, independent of the file
name), and runs that family's real parser to extract documented header fields:
box trees (ISO-BMFF), RIFF/IFF chunks, EBML elements, Ogg pages, TIFF IFD tags,
PNG/JPEG segments, JPEG-2000 boxes, sfnt table directories, MIDI headers, ROM
cartridge headers, disk-image superblocks/footers, ASN.1 DER TLV, HDF5/HDF4/
NetCDF/FITS scientific headers, GPU-texture headers, ML-model container headers,
and the binary serialization wire formats.

When a file carries no fixed magic (many serialization and proprietary project
formats are structurally magicless), the per-extension ``REGISTRY`` selects the
most specific real parser or, for genuinely undocumented/proprietary payloads,
records an honest ``forensic`` disposition -- the format-agnostic forensic
profile (size / sha256 / entropy / byte distribution / string counts), which is
the real, non-fabricated analysis such payloads admit. Nothing here invents fields
it did not read, raw payload is never stored, and the free-text header fields it
does surface are redacted of secrets/PII and length-capped at a single choke point.

The public surface consumed by ``MachineCodeAnalyzer``:

    * ``BinaryFormatParser().analyze(path) -> dict`` with keys
      ``format`` / ``family`` / ``detected_via`` / ``properties`` (list of
      ``(group, name, value)``) / ``sections`` (list of dicts) / ``notes``.
    * ``BinaryFormatParser.EXTS`` -- frozenset of every claimed extension.
    * ``BinaryFormatParser.routing_suffixes()`` -- last-component suffixes for
      the router's ``binary`` class.
    * ``BinaryFormatParser.claims(name)`` -- compound-suffix membership test.
"""

import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.guardrails import scrub

# Bounded header read: enough for every documented header/superblock/box we parse
# without loading multi-gigabyte media into memory.
_HEAD = 1 << 16  # 64 KiB header window
_TAIL = 1 << 16  # 64 KiB tail window (footer-based formats: VHD, DMG)
_MAX_BOXES = 4096
_MAX_TAGS = 4096


# ---------------------------------------------------------------------------
# Per-extension registry (family hint + routing coverage). The magic table below
# overrides these hints whenever a concrete header is recognised at parse time,
# so a hint is never a source of fabricated identification -- only a fallback for
# magicless formats and the routing/coverage census.
# ---------------------------------------------------------------------------
_FAMILY_EXTS: Dict[str, str] = {
    "isobmff": ".3gp2 .3gpp .3gpp2 .f4a .f4b .f4p .m4r .m4p .m4e .3ga .avifs .heics .heifs .hif "
    ".mj2 .cmfa .cmft .cmfv .isma .ismv .f4f .mxf.j2c .braw .r3d .ari .arx",
    "ebml": ".mk3d",
    "riff": ".ani .amv .cdda .16sv .bwav .rf64",
    "ogg": ".ogx .vorbis",
    "asf": ".wm .wmp",
    "mpegts": ".m2t .m2ts .trp .tts .tod .ssif .dvr-ms .wtv .tivo .m2p",
    "mpegps": ".evo .vro .pva .vob",
    "elementary_video": ".264 .265 .266 .h261 .h263 .h264 .h265 .h266 .hevc .hvc .avc .cavs .drc "
    ".vvc .obu .vp8 .vp9 .av1 .ivf .m1v .mpv .mpe .y4m .xvid",
    "adts": ".aacp .adts .m2a .mpga .mp1 .mp2 .mp+",
    "amr": ".awb .amr-wb",
    "codec_raw": ".at3 .at9 .hca .lc3 .msbc .sbc .codec2 .xa .pcm .l16 .s8 .u8 .vox .dtshd .dtsma "
    ".eac3 .mlp .thd .truehd .alac .aa .aax .ram .rmj .rv .viv .nsv .roq .smk .bik .dav "
    ".lxf .gxf .mxf .mxf-op1a .aaf .omfi .dcp .cine .mlv .rdc .lpac .ofr .ofs .dsdiff",
    "midi": ".smf .kar .mxmf .imy .mxm",
    "tracker": ".ams .digi .dsm .gdm .med .mo3 .umx .xmf .j2b",
    "swf": ".swf",
    "forensic_audio": ".ardour .bwpreset .reapeaks .rpp-bak .studioone .drt .fcpevent .fcpproject "
    ".imovielibrary .vpj .aaxplugin .alp .als .aup3 .band .bwproject .clap .component .cpr "
    ".dawproject .flp .logicx .npr .omf .reason .rpp .sesx .song .vst3 .capx .gp3 .gp4 .gp7 .tg "
    ".accurip .adv .alc .aupreset .h2p .nkc .nkr .nkx .rcy .rex .rx2 .sfark .vstpreset .sd2 .sd2f "
    ".camproj .drp .fcpbundle .imovieproj .kdenlive .trec .veg .wlmp .mmp .mmpz .avchd .prproj",
    "tiff": ".bay .cs1 .dcs .drf .k25 .rwz .thm .tiff-f .mrxs .ndpi .scn .svs .vms .vmu .qtk .geotiff "
    ".gtiff .cog .nitf .ntf .nitf21 .lsm .oif .oib .czi .nd2 .lif .ims .cocatalog .cos .eip "
    ".ori .insp .g3 .g4 .fax .efx .rat .tx",
    "jpeg": ".jps .mpo .pns .jfi .jif .lrv .insv",
    "png_img": ".apng .pdn",
    "jp2": ".j2c .jpc .jpm",
    "jxr": ".jxr .hdp .wdp .jxl",
    "jbig": ".jbg .jbig .jbig2 .jb2",
    "exr": ".exr .pfm",
    "gpu_texture": ".astc .basis .ktx .ktx2 .pvr .crn .gim .gtx .pkm .vtf",
    "image_hdr": ".bpg .flif .farbfeld .pam .wbmp .rgb .cur .psp .pspimage .sai .sai2 .mdp .csp .clip "
    ".8bf .rif .riff",
    "psd": ".psd .psdt",
    "xcf": ".xcf",
    "design_forensic": ".afdesign .afphoto .afpub .canva .cdr .cdt .kra .penpot .procreate .fig .indd "
    ".indt .qxd .qxp .sketch .sla .xd .aep .aet .comp .fla .fusion .lottie .tnz .toonz .tvp "
    ".tvpaint .graffle .std .sxd .vsdm .vss .vsx .vtx .wmz .xar .ingp .ksplat .sog",
    "wmf": ".wmf .emf .emz .cgm",
    "fbx": ".fbx",
    "blend": ".blend",
    "usd": ".usd .usdc",
    "gltf": ".glb",
    "openvdb": ".vdb .nvdb",
    "model_3d_forensic": ".amf .bgeo .c4d .hda .lwo .lws .lxo .ma .max .md2 .md3 .md5mesh .nif .smd "
    ".vmf .zpr .ztl .brep .3dm .3dxml .asm .bimx .catdrawing .catpart .catproduct .cgr .dgn .drw "
    ".dwf .dwfx .dwg .dwt .f3d .f3z .fcstd .gh .iam .idw .ifczip .ipn .ipt .jt .layout .nwd .nwf "
    ".par .psm .rfa .rte .rvt .sab .skp .sldasm .slddrw .sldprt .ttm .u3d .vwx .x_b .x_t .obj8 "
    ".ex2 .exodus",
    "zip_pkg": ".pptx .ppsx .potx .pptm .ppsm .potm .sldx .sldm .ppam .xlsb .xlam .xlt .xla .ots .odp "
    ".otp .odt .ott .odg .otg .numbers .key .keynote .pages .dotm .hwpx .glyphs .ufo .aab .apks "
    ".xapk .ipa .appx .appxbundle .appxupload .msix .msixbundle .hap .wgt .tizen .watchface "
    ".xcarchive .love .love2d .unitypackage .apkg .colpkg .cptx .elp .flipchart .h5p .notebook "
    ".scorm .story .anki .epub3 .fb3 .ibooks .onepkg .qgz .qgs .gmlz .kicad_pro .cricut .studio3 "
    ".sublime-package .conda .crx .box .oci .ova .slug .maff .ibooksauthor .rpgproject .yyp "
    ".uproject .spine .tiled .gmx .prz .shw .qpw .et .ett .stc .stw .vssx .vstx .vsdx .pbix .pbit "
    ".twbx .qvf .xva .pvm .utm .bar .cod .sis .sisx .wb2 .wb3 .dpt .prpt .wid .aar .3mf .ora",
    "gzip": ".lzo .snappy .parquet.snappy .rsync .tar.md5 .sin .ftf .kdz .ota .uimage .esd",
    "ar": ".a .la .lo .deb .udeb .ddeb .rlib",
    "rpm": ".rpm .srpm",
    "xar": ".pkg .mpkg .xbps .icon",
    "disk_vhd": ".vhd .vhdx",
    "disk_vmdk": ".vmdk",
    "disk_vdi": ".vdi",
    "disk_qcow": ".qcow .qcow2 .qed .hdd .vswp",
    "disk_iso": ".iso .iso9660 .udf .nrg .cso .rvz .wbfs .gcm",
    "disk_dmg": ".dmg .sparseimage",
    "disk_wim": ".swm .wim",
    "disk_squashfs": ".squashfs .sif .snap .appimage",
    "disk_generic": ".dd .e01 .ex01 .l01 .ad1 .vmfs .rbd",
    "fs_super": ".apfs .btrfs .cramfs .exfat .ext4 .fat .hfsplus .jffs2 .ntfs .romfs .ubifs .ufs .xfs "
    ".zfs .erofs .littlefs .spiffs .hfs .initrd",
    "der": ".cer .crl .crt .der .p7b .p7c .p7m .p7s .pfx .p12 .cades .mobileprovision .cat .shsh2",
    "keystore": ".jks .bks .truststore .keystore .ppk .agekey .hc .tc",
    "hdf5": ".h5 .hdf5 .he5 .mat73 .n5 .hic .mcool .cool .gii .cifti .hdf-eos .weights.h5 .qvd",
    "hdf4": ".hdf .hdf4",
    "netcdf": ".netcdf",
    "grib": ".grb2",
    "fits": ".fts",
    "matlab": ".mat .mexa64 .mexw64",
    "instrument_forensic": ".dm3 .dm4 .dx .emd .jdx .labview .llb .lvproj .prism .pxp .pzfx .qtiplot "
    ".ser .8xp .ggb .gsp .slx .lammpstrj .klm .spm .asdf .ms .acq .cnt .edf+ .eeg .fif .mdf4 "
    ".rrd .set .tdm .tsi .whisper .wsp .bif .analyze .brik .head .afni .dic .minc .mnc .oif .trk "
    ".vtk .mha .mhd .scp .epi .bw .dcm30 .ec .cof",
    "msgpack": ".mpk .rmp",
    "cbor": ".cbor",
    "ion": ".ion",
    "smile": ".smile",
    "ubjson": ".ubjson",
    "marshal": ".marshal",
    "bson": ".bson",
    "flatbuffers": ".flatbuffers",
    "protobuf": ".protobuf",
    "recordio": ".recordio .beton .idx1-ubyte .idx3-ubyte .ubyte .data-00000-of-00001",
    "gguf": ".ggjt .ggla .ggmf .gguf .ggml",
    "ml_forensic": ".awq .embeddings .gptq .lora .mlmodelc .mlx .npu .onnxdata .trtllm .vae "
    ".caffemodel .dlc .engine .hef .mlmodel .mlpackage .model .nemo .params .plan .rknn .bmodel "
    ".cambricon .kmodel .mge .mnn .ncnn .nnp .om .paddle .pdiparams .pdmodel .pdopt .tnn .trt .tvm "
    ".uff .vmfb .xmodel .coreml .nnef .openvino .exl2 .exl3 .fp8 .int8 .q4 .q5 .q8 .sentencepiece "
    ".ftz .magnitude .milvus .cb .cbm .crfsuite .h2o .lgb .surprise .xgb .eqx .orbax .savedmodel "
    ".task .ep .jit .pte .ptl .torchscript .dgraph .kudu .carbondata .hudi .vortex .rcfile "
    ".sequencefile",
    "sfnt": ".ttf .otf .ttc .otc .dfont .suit .vf",
    "woff": ".woff",
    "woff2": ".woff2",
    "eot": ".eot",
    "type1": ".pfb",
    "font_forensic": ".afm .gf .glyphs .pk .sfd .tfm .ufo .vfb",
    "dvi": ".dvi",
    "djvu": ".djv .djvu",
    "pdf": ".pdfa .oxps .xps",
    "pcl": ".pcl .pwg .urf .ppf",
    "doc_forensic": ".602 .hml .mcw .stw .uof .uos .vor .zabw .uot .wri .aux .glo .lof .lot .dps .pot "
    ".pps .ppt .prz .shw .ett .wb1 .xlr .qpw .prpt .rpt .wid .csvw .csvy .azw .azw3 .cbz .kfx .lit "
    ".lrf .lrx .mobi .prc .cb7 .cbr .cbt .azw4 .cba .ceb .snb .tcr .tr2 .tr3 .kf8 .dpt .sti .stc "
    ".et .dbc .dbs .dmd .erwin .accdr .bacpac .dacpac .ddb .ib .ibdata .laccdb .mda .mde .ns "
    ".tokudb .abinitio .ispac .mp .talend .ppam .sldm .keynote",
    "rom_nes": ".nes",
    "rom_n64": ".n64 .z64 .v64",
    "rom_snes": ".smc .sfc",
    "rom_gb": ".gb .gbc",
    "rom_gba": ".gba",
    "rom_nds": ".nds",
    "rom_3ds": ".3ds .cia .xci",
    "rom_genesis": ".gen .md .smd",
    "rom_generic": ".a26 .a78 .col .int .lnx .pce .gg .sms .32x .ngp .pbp .bios .chd .rvz .wbfs .gcm .cso",
    "pcap": ".pcap",
    "pcapng": ".pcapng",
    "snoop": ".snoop",
    "trace_forensic": ".ctf .nettrace .nsys-rep .wtl .anydesk .teamviewer .ios .r2 .idb .i64 .bndb .axiom",
    "bplist": ".webarchive .pkpass",
    "firmware_forensic": ".cbfs .coreboot .dfu .eep .ewp .fd .ifd .ihx .jic .mot .mpy .nodemcu .out "
    ".rbf .rom .uvprojx .vbios .hmi .scada .bit .jed .mcs .pof .qpf .sof .xpr .xsa .acd .ap15 "
    ".project .s7p .tp .urp .brd .dsn .kicad_pcb .kicad_sch .opj .pcb .pcbdoc .prjpcb .sch .schdoc "
    ".factory .hsm .lbrn .lbrn2 .mcam .ufp .adams .aedt .cae .cst .fmu .hfss .mph .plt .ssp .wbpj "
    ".qcp .qsproj",
    "geo_forensic": ".adf .aprx .e00 .ecw .gpkg .mbtiles .mxd .o5m .pbf .pmtiles .s57 .sbn .shx .shp "
    ".fgb .flatgeobuf .geoparquet .id .qix .atx .00t .dtm .hec .leapfrog .wrf .hgt .adrg .bsb "
    ".cadrg .cm93 .dted .kap .rpf .s101 .s63 .vpf .sbx .wko .blt .esti .pwb",
    "stat_forensic": ".dht .nsdstat .omt .spo .ssd01 .wf2 .zsav .jasp .lim .mpj",
    "misc_forensic": ".sln .vcxproj .gch .pch .vbproj .fsproj .gem .jmod .phar .pyd .rproj .crate "
    ".sdist .code-workspace .dbproj .iml .ipr .iws .kate-project .sublime-project "
    ".sublime-workspace .ex4 .ex5 .nt8 .qvw .twb .app .nca .jwk .jwks .hdt .safariextz .360 "
    ".ambix .arexperience .rcproject .reality .splat .spz .tbe .vrm .ase .aseprite .bnk .fsb "
    ".rpyc .unity .unity3d .elc .luac .mpp .mpt .fmb .fmx .axmodel .run .swo .swp .386 .acm .ax "
    ".mst",
    "zip_bundle": ".daisy .ipsw .xcassets .xcodeproj .xcworkspace .flatpak",
    "bundle_forensic": ".dext .kext .framework .prefpane .saver .qlgenerator .mdimporter .xcframework .hbc",
    "partial": ".crdownload .download .temp .tmp",
    "svgz": ".svgz",
    "mjpeg": ".mjpg",
}

# ext -> family (first assignment wins: earlier, more-specific families dominate).
REGISTRY: Dict[str, str] = {}
for _fam, _s in _FAMILY_EXTS.items():
    for _e in _s.split():
        REGISTRY.setdefault(_e, _fam)


class BinaryFormatParser:
    """Magic-driven structural parser for the non-executable binary universe."""

    EXTS = frozenset(REGISTRY)

    # ------------------------------------------------------------------
    # Coverage / routing helpers
    # ------------------------------------------------------------------
    @classmethod
    def routing_suffixes(cls) -> frozenset:
        """Last-component suffixes (e.g. ``.tar.md5`` -> ``.md5``) for the router."""
        return frozenset(("." + e.rsplit(".", 1)[-1]) for e in cls.EXTS)

    @classmethod
    def claims(cls, name_or_ext: str) -> bool:
        """True if any dotted suffix of the name is a registered format extension."""
        low = str(name_or_ext).lower()
        if low in cls.EXTS:
            return True
        name = Path(low).name
        parts = name.split(".")
        for i in range(1, len(parts)):
            if "." + ".".join(parts[i:]) in cls.EXTS:
                return True
        return False

    @classmethod
    def family_for(cls, name_or_ext: str) -> Optional[str]:
        low = str(name_or_ext).lower()
        if low in REGISTRY:
            return REGISTRY[low]
        name = Path(low).name
        parts = name.split(".")
        for i in range(1, len(parts)):
            suf = "." + ".".join(parts[i:])
            if suf in REGISTRY:
                return REGISTRY[suf]
        return None

    # ==================================================================
    # Magic signature table (offset, magic, family). First match wins.
    # These are real content signatures; a match overrides the ext hint.
    # ==================================================================
    _MAGIC: Tuple[Tuple[int, bytes, str], ...] = (
        (0, b"\x1a\x45\xdf\xa3", "ebml"),
        (0, b"RIFF", "riff"),
        (0, b"RF64", "riff"),
        (0, b"OggS", "ogg"),
        (0, b"\x30\x26\xb2\x75\x8e\x66\xcf\x11", "asf"),
        # Documented video-codec containers (previously forensic-only under
        # ``codec_raw``): a concrete signature routes them to the real decoder.
        (0, b"BIK", "codec_video"),
        (0, b"KB2", "codec_video"),  # Bink 1 / Bink 2
        (0, b"SMK2", "codec_video"),
        (0, b"SMK4", "codec_video"),  # Smacker
        (0, b".RMF", "codec_video"),  # RealMedia
        (0, b"\x06\x0e\x2b\x34\x02\x05\x01\x01", "codec_video"),  # MXF (SMPTE KLV)
        (0, b"NSVf", "codec_video"),
        (0, b"NSVs", "codec_video"),  # Nullsoft NSV
        (0, b"MThd", "midi"),
        (0, b"FWS", "swf"),
        (0, b"CWS", "swf"),
        (0, b"ZWS", "swf"),
        (0, b"II\x2a\x00", "tiff"),
        (0, b"MM\x00\x2a", "tiff"),
        (0, b"II\xbc", "jxr"),
        (0, b"\x89PNG\r\n\x1a\n", "png_img"),
        (0, b"\xff\xd8\xff", "jpeg"),
        (0, b"\x00\x00\x00\x0cjP  \r\n\x87\n", "jp2"),
        (0, b"\xff\x4f\xff\x51", "jp2"),
        (0, b"\x00\x00\x00\x0cJXL \r\n\x87\n", "jxr"),  # JPEG XL container
        (0, b"\xff\x0a", "jxr"),  # JPEG XL codestream
        (0, b"\x97JB2\r\n\x1a\n", "jbig"),
        (0, b"\x76\x2f\x31\x01", "exr"),
        (0, b"#?RADIANCE", "exr"),
        (0, b"#?RGBE", "exr"),
        (0, b"\xabKTX 11\xbb\r\n\x1a\n", "gpu_texture"),
        (0, b"\xabKTX 20\xbb\r\n\x1a\n", "gpu_texture"),
        (0, b"\x13\xab\xa1\x5c", "gpu_texture"),  # ASTC
        (0, b"PVR\x03", "gpu_texture"),
        (44, b"PVR!", "gpu_texture"),
        (0, b"DDS ", "gpu_texture"),
        (0, b"\x73\x42", "gpu_texture"),  # Basis Universal 'sB'
        (0, b"GIF8", "gif"),
        (0, b"BM", "bmp"),
        (0, b"\x00\x00\x01\x00", "ico"),
        (0, b"\x00\x00\x02\x00", "ico"),
        (0, b"icns", "icns"),
        (0, b"BPG\xfb", "image_hdr"),  # BPG
        (0, b"FLIF", "image_hdr"),
        (0, b"farbfeld", "image_hdr"),
        (0, b"8BPS", "psd"),
        (0, b"gimp xcf ", "xcf"),
        (0, b"Kaydara FBX Binary", "fbx"),
        (0, b"BLENDER", "blend"),
        (0, b"PXR-USDC", "usd"),
        (0, b"glTF", "gltf"),
        (0, b"NanoVDB", "openvdb"),
        (0, b" BD", "openvdb"),
        (0, b"PK\x03\x04", "zip_pkg"),
        (0, b"PK\x05\x06", "zip_pkg"),
        (0, b"PK\x07\x08", "zip_pkg"),
        (0, b"\x1f\x8b", "gzip"),
        (0, b"!<arch>\n", "ar"),
        (0, b"\xed\xab\xee\xdb", "rpm"),
        (0, b"xar!", "xar"),
        (0, b"7z\xbc\xaf\x27\x1c", "sevenzip"),
        (0, b"Rar!\x1a\x07", "rar"),
        (0, b"MSCF", "cab"),
        (0, b"SQLite format 3\x00", "sqlite"),
        (0, b"\x89HDF\r\n\x1a\n", "hdf5"),
        (0, b"\x0e\x03\x13\x01", "hdf4"),
        (0, b"CDF\x01", "netcdf"),
        (0, b"CDF\x02", "netcdf"),
        (0, b"GRIB", "grib"),
        (0, b"SIMPLE  =", "fits"),
        (0, b"MATLAB 5.0", "matlab"),
        (0, b"\x93NUMPY", "npy"),
        (0, b"GGUF", "gguf"),
        (0, b"ggjt", "gguf"),
        (0, b"ggla", "gguf"),
        (0, b"ggmf", "gguf"),
        (0, b"ggml", "gguf"),
        (0, b"tjgg", "gguf"),
        (4, b"TFL3", "tflite"),
        (0, b"\xe0\x01\x00\xea", "ion"),
        (0, b":)\n", "smile"),
        (0, b"\x04\x08", "marshal"),
        (0, b"Extended Module: ", "tracker"),  # FastTracker II XM
        (0, b"IMPM", "tracker"),  # Impulse Tracker IT
        (0, b"\x00\x01\x00\x00", "sfnt"),
        (0, b"OTTO", "sfnt"),
        (0, b"true", "sfnt"),
        (0, b"typ1", "sfnt"),
        (0, b"ttcf", "sfnt"),
        (0, b"wOFF", "woff"),
        (0, b"wOF2", "woff2"),
        (0, b"\x80\x01", "type1"),
        (0, b"\xf7\x02", "dvi"),
        (0, b"AT&TFORM", "djvu"),
        (0, b"%PDF-", "pdf"),
        (0, b"\xa1\xb2\xc3\xd4", "pcap"),
        (0, b"\xd4\xc3\xb2\xa1", "pcap"),
        (0, b"\xa1\xb2\x3c\x4d", "pcap"),
        (0, b"\x4d\x3c\xb2\xa1", "pcap"),
        (0, b"\x0a\x0d\x0d\x0a", "pcapng"),
        (0, b"snoop\x00\x00\x00", "snoop"),
        (0, b"bplist00", "bplist"),
        (0, b"NES\x1a", "rom_nes"),
        (0, b"\x80\x37\x12\x40", "rom_n64"),
        (0, b"\x37\x80\x40\x12", "rom_n64"),
        (0, b"\x40\x12\x37\x80", "rom_n64"),
        (0, b"MComprHD", "rom_generic"),  # CHD
        (0, b"vhdxfile", "disk_vhd"),
        (0, b"QFI\xfb", "disk_qcow"),
        (0, b"QED\x00", "disk_qcow"),  # QEMU Enhanced Disk
        (0, b"KDMV", "disk_vmdk"),
        (0, b"# Disk DescriptorFile", "disk_vmdk"),
        (0, b"<<< ", "disk_vdi"),
        (0, b"MSWIM\x00\x00\x00", "disk_wim"),
        (0, b"hsqs", "disk_squashfs"),
        (0, b"sqsh", "disk_squashfs"),
        (0, b"-rom1fs-", "fs_super"),
        (0, b"\x45\x3d\xcd\x28", "fs_super"),  # cramfs LE
        (0, b"\x28\xcd\x3d\x45", "fs_super"),  # cramfs BE
        (0, b"EVF\x09\x0d\x0a\xff\x00", "disk_generic"),  # EWF/E01
        (0, b"\x1bLua", "lua"),
        (0, b";ELC", "elc"),
        (0, b"\x01\x00\x00\x00 EMF", "wmf"),  # EMF (rare fixed)
        (0, b"\xd7\xcd\xc6\x9a", "wmf"),  # placeable WMF
        (0, b"HEC", "grib"),
    )

    # ------------------------------------------------------------------
    def analyze(self, path: Any, ext: Optional[str] = None) -> Dict[str, Any]:
        """Parse one binary file and return structural metadata (never raises)."""
        p = Path(path)
        if ext is None:
            ext = self.family_for(p.name)
        out: Dict[str, Any] = {
            "format": None,
            "family": None,
            "detected_via": None,
            "properties": [],
            "sections": [],
            "notes": None,
        }
        try:
            with open(p, "rb") as fh:
                head = fh.read(_HEAD)
        except OSError as err:
            out["notes"] = f"read failed: {type(err).__name__}: {err}"
            return out
        if not head:
            out["format"], out["family"], out["detected_via"] = (
                "empty",
                "empty",
                "content",
            )
            return out

        fam = self._sniff(head)
        via = "magic"
        if fam is None:
            fam = self.family_for(p.name)
            via = "extension" if fam else None
        out["detected_via"] = via

        handler = self._HANDLERS.get(fam)
        if handler is not None:
            try:
                handler(self, p, head, out)
            except (
                Exception
            ) as err:  # noqa: BLE001 - one bad file never sinks the batch
                out["notes"] = f"deep-parse partial: {type(err).__name__}: {err}"
                if out["format"] is None:
                    out["format"] = self._FAMILY_LABEL.get(fam, fam)
            if out["family"] is None:
                out["family"] = self._FAMILY_GROUP.get(fam, "binary")
        else:
            # No bespoke reader: honest forensic disposition. The forensic base
            # (size/sha256/entropy/strings) is supplied by the caller's profiler.
            label = self._FAMILY_LABEL.get(fam, "binary (forensic profile only)")
            out["format"] = label
            out["family"] = self._FAMILY_GROUP.get(fam, "binary")
            out["notes"] = (
                out["notes"] or "structure not decoded; forensic profile only"
            )
        return out

    # ------------------------------------------------------------------
    def _sniff(self, head: bytes) -> Optional[str]:
        for off, magic, fam in self._MAGIC:
            if head[off : off + len(magic)] == magic:
                # RIFF/ISO refine below via form type / brand.
                return fam
        # ISO-BMFF: a 'ftyp'/'styp'/'moov'/'mdat' box at offset 4.
        if len(head) >= 12 and head[4:8] in (
            b"ftyp",
            b"styp",
            b"moov",
            b"mdat",
            b"free",
            b"skip",
        ):
            return "isobmff"
        # MPEG transport stream: 0x47 sync at 0 and at 188/192.
        if head[:1] == b"\x47" and (
            len(head) < 189
            or head[188:189] == b"\x47"
            or (len(head) >= 193 and head[192:193] == b"\x47")
        ):
            return "mpegts"
        # MPEG program stream / elementary start codes.
        if head[:4] == b"\x00\x00\x01\xba":
            return "mpegps"
        if head[:4] in (b"\x00\x00\x00\x01",) or head[:3] == b"\x00\x00\x01":
            return "elementary_video"
        # ADTS AAC sync (12 set bits).
        if len(head) >= 2 and head[0] == 0xFF and (head[1] & 0xF6) == 0xF0:
            return "adts"
        # AMR / AMR-WB signatures.
        if head[:6] == b"#!AMR\n" or head[:9] == b"#!AMR-WB\n":
            return "amr"
        # DER: ASN.1 SEQUENCE (0x30) with definite long-form length.
        if head[:1] == b"\x30" and len(head) >= 2 and head[1] in (0x81, 0x82, 0x83):
            return "der"
        # JKS/BKS keystore.
        if head[:4] == b"\xfe\xed\xfe\xed":
            return "keystore"
        return None

    # ==================================================================
    # ISO base media file format (MP4/MOV/HEIF/3GP/CMAF/...)
    # ==================================================================
    def _p_isobmff(self, p, head, out):
        data = head
        out["format"] = "ISO base media (ISO-BMFF)"
        out["family"] = "video"
        boxes: List[Tuple[str, int, int]] = []
        self._iso_walk(data, 0, len(data), boxes, 0)
        brand = None
        for typ, off, size in boxes:
            if typ == "ftyp":
                brand = data[off + 8 : off + 12].decode("latin-1", "replace").strip()
                minor = (
                    struct.unpack(">I", data[off + 12 : off + 16])[0]
                    if off + 16 <= len(data)
                    else None
                )
                compat = []
                q = off + 16
                while q + 4 <= off + size and len(compat) < 16:
                    compat.append(data[q : q + 4].decode("latin-1", "replace").strip())
                    q += 4
                self._prop(out, "isobmff", "major_brand", brand)
                if minor is not None:
                    self._prop(out, "isobmff", "minor_version", minor)
                if compat:
                    self._prop(
                        out,
                        "isobmff",
                        "compatible_brands",
                        ",".join(c for c in compat if c),
                    )
        top = [b for b in boxes if b[2] > 0]
        self._prop(out, "isobmff", "top_level_boxes", len(top))
        for typ, off, size in top[:_MAX_BOXES]:
            out["sections"].append(self._sec(typ, "iso-box", off, size))
        # Brand -> concrete label.
        brand_map = {
            "isom": "MP4",
            "mp41": "MP4",
            "mp42": "MP4",
            "M4A ": "M4A audio",
            "M4V ": "M4V video",
            "qt  ": "QuickTime MOV",
            "3gp": "3GPP",
            "3g2": "3GPP2",
            "heic": "HEIF/HEIC",
            "heix": "HEIF",
            "mif1": "HEIF",
            "avif": "AVIF",
            "mj2s": "Motion JPEG 2000",
            "dash": "MP4 (DASH)",
            "cmfc": "CMAF",
            "f4v": "Flash MP4",
        }
        if brand:
            for k, v in brand_map.items():
                if brand.startswith(k.strip()):
                    out["format"] = f"ISO-BMFF ({v})"
                    break
        if brand and brand.strip().lower().startswith(("m4a", "f4a", "f4b")):
            out["family"] = "audio"

    def _iso_walk(self, data, start, end, boxes, depth):
        off = start
        n = 0
        while off + 8 <= end and n < _MAX_BOXES:
            size, typ = (
                struct.unpack(">I", data[off : off + 4])[0],
                data[off + 4 : off + 8],
            )
            hdr = 8
            if size == 1:
                if off + 16 > end:
                    break
                size = struct.unpack(">Q", data[off + 8 : off + 16])[0]
                hdr = 16
            elif size == 0:
                size = end - off
            try:
                t = typ.decode("ascii")
            except UnicodeDecodeError:
                break
            boxes.append((t, off, size))
            if size < hdr:
                break
            off += size
            n += 1

    # ==================================================================
    # RIFF (AVI / WAV / WebP / ANI / RF64 ...)
    # ==================================================================
    _RIFF_FORM = {
        b"AVI ": ("AVI video", "video"),
        b"WAVE": ("WAV audio", "audio"),
        b"WEBP": ("WebP image", "image"),
        b"ACON": ("Windows animated cursor", "image"),
        b"RMID": ("RIFF MIDI", "audio"),
        b"CDDA": ("CD Digital Audio", "audio"),
        b"BW64": ("Broadcast WAV 64", "audio"),
        b"ds64": ("RF64 audio", "audio"),
    }

    def _p_riff(self, p, head, out):
        data = head
        is_rf64 = data[:4] == b"RF64"
        out["format"] = "RIFF container"
        out["family"] = "container"
        form = data[8:12]
        label, fam = self._RIFF_FORM.get(
            form, (f"RIFF/{form.decode('latin-1','replace')}", "container")
        )
        if is_rf64:
            label = "RF64 / BWF-64 audio"
            fam = "audio"
        out["format"] = label
        out["family"] = fam
        self._prop(out, "riff", "form_type", form.decode("latin-1", "replace"))
        total = struct.unpack("<I", data[4:8])[0]
        self._prop(out, "riff", "declared_size", total + 8)
        off = 12
        chunks = 0
        while off + 8 <= len(data) and chunks < _MAX_BOXES:
            cid = data[off : off + 4]
            csz = struct.unpack("<I", data[off + 4 : off + 8])[0]
            out["sections"].append(
                self._sec(cid.decode("latin-1", "replace"), "riff-chunk", off, csz)
            )
            chunks += 1
            if cid == b"fmt " and off + 8 + 16 <= len(data):
                afmt, ch, sr, br, ba, bps = struct.unpack(
                    "<HHIIHH", data[off + 8 : off + 8 + 16]
                )
                self._prop(out, "wav", "audio_format", afmt)
                self._prop(out, "wav", "channels", ch)
                self._prop(out, "wav", "sample_rate", sr)
                self._prop(out, "wav", "bits_per_sample", bps)
            if cid == b"strh" and off + 8 + 4 <= len(data):
                self._prop(
                    out,
                    "avi",
                    "stream_type",
                    data[off + 8 : off + 12].decode("latin-1", "replace"),
                )
            off += 8 + csz + (csz & 1)

    # ==================================================================
    # Matroska / WebM (EBML)
    # ==================================================================
    def _p_ebml(self, p, head, out):
        data = head
        out["format"] = "Matroska / WebM (EBML)"
        out["family"] = "video"
        # Read the EBML DocType from the header element.
        idx = data.find(b"\x42\x82")  # DocType element id
        if idx >= 0 and idx + 3 < len(data):
            ln = data[idx + 2]
            size = ln & 0x7F
            doctype = data[idx + 3 : idx + 3 + size].decode("latin-1", "replace")
            self._prop(out, "ebml", "doctype", doctype)
            if doctype == "webm":
                out["format"] = "WebM (EBML)"
        self._prop(out, "ebml", "signature", "1A45DFA3")

    # ==================================================================
    # Ogg
    # ==================================================================
    def _p_ogg(self, p, head, out):
        data = head
        out["format"] = "Ogg container"
        out["family"] = "audio"
        codec = None
        if b"\x01vorbis" in data[:64]:
            codec, out["format"] = "Vorbis", "Ogg Vorbis"
        elif b"OpusHead" in data[:64]:
            codec, out["format"] = "Opus", "Ogg Opus"
        elif b"\x7fFLAC" in data[:64]:
            codec, out["format"] = "FLAC", "Ogg FLAC"
        elif b"\x80theora" in data[:64]:
            codec, out["format"], out["family"] = "Theora", "Ogg Theora", "video"
        elif b"Speex" in data[:64]:
            codec, out["format"] = "Speex", "Ogg Speex"
        if codec:
            self._prop(out, "ogg", "codec", codec)
        # Count Ogg pages in the header window.
        self._prop(out, "ogg", "pages_in_header", data.count(b"OggS"))

    # ==================================================================
    # ASF / WMV / WMA
    # ==================================================================
    # ASF GUIDs (little-endian byte order as stored on disk).
    _ASF_HEADER = b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c"
    _ASF_FILEPROPS = b"\xa1\xdc\xab\x8c\x47\xa9\xcf\x11\x8e\xe4\x00\xc0\x0c\x20\x53\x65"
    _ASF_AUDIO_STREAM = (
        b"\x40\x9e\x69\xf8\x4d\x5b\xcf\x11\xa8\xfd\x00\x80\x5f\x5c\x44\x2b"
    )

    def _p_asf(self, p, head, out):
        data = head
        out["format"] = "ASF (Windows Media)"
        out["family"] = "video"
        # Header Object: GUID(16) + uint64 size + uint32 num objects + 2 reserved.
        if data[:16] == self._ASF_HEADER and len(data) >= 30:
            hsize = struct.unpack("<Q", data[16:24])[0]
            nobj = struct.unpack("<I", data[24:28])[0]
            self._prop(out, "asf", "header_size", hsize)
            self._prop(out, "asf", "header_objects", nobj)
        # File Properties Object -> creation time / duration / bitrate.
        i = data.find(self._ASF_FILEPROPS)
        if i >= 0 and i + 24 + 80 <= len(data):
            base = i + 24  # skip GUID(16) + object size(8)
            play_dur = struct.unpack("<Q", data[base + 40 : base + 48])[
                0
            ]  # 100-ns units
            preroll = struct.unpack("<Q", data[base + 56 : base + 64])[0]  # ms
            max_bitrate = struct.unpack("<I", data[base + 76 : base + 80])[0]
            dur_ms = max(0, play_dur // 10000 - preroll)
            self._prop(out, "asf", "duration_ms", dur_ms)
            self._prop(out, "asf", "max_bitrate", max_bitrate)
        # Audio-only ASF -> WMA.
        if self._ASF_AUDIO_STREAM in data and self._find_asf_video(data) is None:
            out["format"] = "ASF / WMA (audio)"
            out["family"] = "audio"

    @staticmethod
    def _find_asf_video(data):
        video_guid = b"\xc0\xef\x19\xbc\x4d\x5b\xcf\x11\xa8\xfd\x00\x80\x5f\x5c\x44\x2b"
        i = data.find(video_guid)
        return i if i >= 0 else None

    # ==================================================================
    # MPEG transport / program / elementary streams
    # ==================================================================
    def _p_mpegts(self, p, head, out):
        out["format"] = "MPEG-2 transport stream"
        out["family"] = "video"
        # Packet size: 188 (TS), 192 (M2TS/timestamped), 204 (FEC).
        size = 188
        for cand in (188, 192, 204):
            if head[:1] == b"\x47" and (
                len(head) <= cand or head[cand : cand + 1] == b"\x47"
            ):
                size = cand
                break
        self._prop(out, "mpegts", "packet_size", size)
        self._prop(out, "mpegts", "packets_in_header", len(head) // size)

    def _p_mpegps(self, p, head, out):
        out["format"] = "MPEG program stream"
        out["family"] = "video"
        self._prop(out, "mpegps", "start_code", "000001BA")

    def _p_elementary(self, p, head, out):
        out["format"] = "Raw video elementary stream"
        out["family"] = "video"
        # First NAL type for H.264/265 Annex-B.
        i = head.find(b"\x00\x00\x01")
        if i >= 0 and i + 3 < len(head):
            nal = head[i + 3]
            self._prop(out, "video", "first_nal_byte", hex(nal))
        self._prop(
            out, "video", "annexb_start_codes", head[:4096].count(b"\x00\x00\x01")
        )

    def _p_adts(self, p, head, out):
        out["format"] = "AAC (ADTS)"
        out["family"] = "audio"
        if len(head) >= 7 and head[0] == 0xFF:
            profile = (head[2] >> 6) & 0x3
            sr_idx = (head[2] >> 2) & 0xF
            ch = ((head[2] & 0x1) << 2) | ((head[3] >> 6) & 0x3)
            rates = [
                96000,
                88200,
                64000,
                48000,
                44100,
                32000,
                24000,
                22050,
                16000,
                12000,
                11025,
                8000,
                7350,
            ]
            self._prop(out, "aac", "profile", ["Main", "LC", "SSR", "LTP"][profile])
            if sr_idx < len(rates):
                self._prop(out, "aac", "sample_rate", rates[sr_idx])
            self._prop(out, "aac", "channels", ch)

    def _p_amr(self, p, head, out):
        out["format"] = "AMR audio"
        out["family"] = "audio"
        if head[:9] == b"#!AMR-WB\n":
            out["format"] = "AMR-WB (wideband)"
            self._prop(out, "amr", "variant", "wideband")
        else:
            self._prop(out, "amr", "variant", "narrowband")

    # ==================================================================
    # Documented video-codec containers (Bink / Smacker / RealMedia / MXF / NSV)
    # ==================================================================
    def _p_codec(self, p, head, out):
        data = head
        out["family"] = "video"
        # --- Bink (BIKx) / Bink 2 (KB2x): dimensions live at 0x14/0x18 ---
        if data[:3] in (b"BIK", b"KB2"):
            rev = chr(data[3]) if len(data) > 3 and 32 <= data[3] < 127 else "?"
            out["format"] = (
                "Bink 2 video" if data[:3] == b"KB2" else "Bink video"
            ) + f" (rev {rev})"
            if len(data) >= 0x1C:
                fsize, nframes, largest = struct.unpack("<III", data[4:16])
                width, height = struct.unpack("<II", data[0x14:0x1C])
                self._prop(out, "bink", "frames", nframes)
                self._prop(out, "bink", "width", width)
                self._prop(out, "bink", "height", height)
                self._prop(out, "bink", "largest_frame_bytes", largest)
            return
        # --- Smacker (SMK2/SMK4): width/height/frames ---
        if data[:3] == b"SMK" and len(data) >= 4 and data[3:4] in (b"2", b"4"):
            out["format"] = f"Smacker video (SMK{chr(data[3])})"
            if len(data) >= 0x10:
                width, height, frames = struct.unpack("<III", data[4:16])
                self._prop(out, "smacker", "width", width)
                self._prop(out, "smacker", "height", height)
                self._prop(out, "smacker", "frames", frames)
            return
        # --- RealMedia (.RMF header + PROP media-properties chunk) ---
        if data[:4] == b".RMF":
            out["format"] = "RealMedia (RM/RMVB)"
            if len(data) >= 18:
                objver = struct.unpack(">H", data[8:10])[0]
                fver, nheaders = struct.unpack(">II", data[10:18])
                self._prop(out, "realmedia", "object_version", objver)
                self._prop(out, "realmedia", "file_version", fver)
                self._prop(out, "realmedia", "header_count", nheaders)
            i = data.find(b"PROP")
            if i >= 0 and i + 34 <= len(data):
                try:
                    avg_bitrate = struct.unpack(">I", data[i + 14 : i + 18])[0]
                    num_packets = struct.unpack(">I", data[i + 26 : i + 30])[0]
                    duration = struct.unpack(">I", data[i + 30 : i + 34])[0]
                    self._prop(out, "realmedia", "avg_bitrate", avg_bitrate)
                    self._prop(out, "realmedia", "num_packets", num_packets)
                    self._prop(out, "realmedia", "duration_ms", duration)
                except struct.error:
                    pass
            return
        # --- MXF (SMPTE 377M): partition-pack KLV, decode version from value ---
        if data[:8] == b"\x06\x0e\x2b\x34\x02\x05\x01\x01":
            out["format"] = "MXF (SMPTE 377M)"
            self._prop(out, "mxf", "klv_key", data[:16].hex())
            if len(data) >= 17:
                blen = data[16]
                vstart = {0x81: 18, 0x82: 19, 0x83: 20, 0x84: 21}.get(
                    blen, 17 if blen < 0x80 else None
                )
                if vstart and vstart + 4 <= len(data):
                    major, minor = struct.unpack(">HH", data[vstart : vstart + 4])
                    self._prop(out, "mxf", "version", f"{major}.{minor}")
            return
        # --- Nullsoft Streaming Video ---
        if data[:3] == b"NSV":
            out["format"] = "Nullsoft Streaming Video (NSV)"
            self._prop(
                out, "nsv", "kind", "headered" if data[:4] == b"NSVf" else "streamed"
            )
            return
        out["format"] = "video codec stream"

    # ==================================================================
    # MIDI
    # ==================================================================
    def _p_midi(self, p, head, out):
        data = head
        out["format"] = "Standard MIDI file"
        out["family"] = "audio"
        if data[:4] == b"MThd" and len(data) >= 14:
            fmt, ntrks, div = struct.unpack(">HHH", data[8:14])
            self._prop(out, "midi", "format", fmt)
            self._prop(out, "midi", "tracks", ntrks)
            if div & 0x8000:
                self._prop(out, "midi", "division", f"SMPTE {div}")
            else:
                self._prop(out, "midi", "ticks_per_quarter", div)
            for m in range(min(ntrks, _MAX_BOXES)):
                pass

    # ==================================================================
    # SWF
    # ==================================================================
    def _p_swf(self, p, head, out):
        data = head
        sig = data[:3].decode("latin-1", "replace")
        comp = {"FWS": "uncompressed", "CWS": "zlib", "ZWS": "LZMA"}.get(sig, "unknown")
        out["format"] = f"Adobe Flash SWF ({comp})"
        out["family"] = "video"
        if len(data) >= 4:
            self._prop(out, "swf", "version", data[3])
            self._prop(out, "swf", "compression", comp)
        if len(data) >= 8:
            self._prop(out, "swf", "file_length", struct.unpack("<I", data[4:8])[0])

    # ==================================================================
    # TIFF (+ camera raw / whole-slide / GeoTIFF)
    # ==================================================================
    def _p_tiff(self, p, head, out):
        data = head
        endian = "<" if data[:2] == b"II" else ">"
        out["format"] = "TIFF"
        out["family"] = "image"
        ifd_off = struct.unpack(endian + "I", data[4:8])[0]
        if ifd_off + 2 > len(data):
            self._prop(out, "tiff", "byte_order", "little" if endian == "<" else "big")
            return
        count = struct.unpack(endian + "H", data[ifd_off : ifd_off + 2])[0]
        self._prop(out, "tiff", "byte_order", "little" if endian == "<" else "big")
        self._prop(out, "tiff", "ifd0_entries", count)
        width = height = bps = comp = photometric = None
        geo = False
        for i in range(min(count, _MAX_TAGS)):
            base = ifd_off + 2 + i * 12
            if base + 12 > len(data):
                break
            tag, typ, cnt = struct.unpack(endian + "HHI", data[base : base + 8])
            val = struct.unpack(endian + "I", data[base + 8 : base + 12])[0]
            sval = struct.unpack(endian + "H", data[base + 8 : base + 10])[0]
            if tag == 256:
                width = val if typ == 4 else sval
            elif tag == 257:
                height = val if typ == 4 else sval
            elif tag == 258:
                bps = sval
            elif tag == 259:
                comp = sval
            elif tag == 262:
                photometric = sval
            elif tag in (34735, 34736, 34737):
                geo = True
        if width:
            self._prop(out, "tiff", "width", width)
        if height:
            self._prop(out, "tiff", "height", height)
        if bps:
            self._prop(out, "tiff", "bits_per_sample", bps)
        comp_map = {
            1: "none",
            2: "CCITT",
            5: "LZW",
            6: "JPEG(old)",
            7: "JPEG",
            8: "Deflate",
            32773: "PackBits",
            34712: "JPEG2000",
        }
        if comp is not None:
            self._prop(out, "tiff", "compression", comp_map.get(comp, str(comp)))
        if geo:
            self._prop(out, "tiff", "geotiff", "yes (GeoKey tags present)")
            out["format"] = "GeoTIFF"

    # ==================================================================
    # JPEG (+ MPO / stereo)
    # ==================================================================
    def _p_jpeg(self, p, head, out):
        data = head
        out["format"] = "JPEG"
        out["family"] = "image"
        off = 2
        width = height = None
        components = None
        segs = 0
        while off + 4 <= len(data) and segs < _MAX_BOXES:
            if data[off] != 0xFF:
                break
            marker = data[off + 1]
            if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
                off += 2
                continue
            seglen = struct.unpack(">H", data[off + 2 : off + 4])[0]
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB):
                if off + 9 <= len(data):
                    prec = data[off + 4]
                    height, width = struct.unpack(">HH", data[off + 5 : off + 9])
                    components = data[off + 9] if off + 9 < len(data) else None
                    self._prop(out, "jpeg", "precision", prec)
            if marker == 0xE1 and data[off + 4 : off + 10] == b"Exif\x00\x00":
                self._prop(out, "jpeg", "exif", "present")
            if data[off + 4 : off + 8] == b"MPF\x00":
                out["format"] = "JPEG MPO (multi-picture)"
                self._prop(out, "jpeg", "mpo", "yes")
            off += 2 + seglen
            segs += 1
            if marker == 0xDA:  # start of scan
                break
        if width:
            self._prop(out, "jpeg", "width", width)
        if height:
            self._prop(out, "jpeg", "height", height)
        if components:
            self._prop(out, "jpeg", "components", components)
            out["format"] = (
                out["format"]
                if "MPO" in out["format"]
                else ("JPEG (grayscale)" if components == 1 else "JPEG")
            )

    # ==================================================================
    # PNG (+ APNG)
    # ==================================================================
    def _p_png(self, p, head, out):
        data = head
        out["format"] = "PNG"
        out["family"] = "image"
        off = 8
        is_apng = False
        while off + 8 <= len(data):
            length = struct.unpack(">I", data[off : off + 4])[0]
            ctype = data[off + 4 : off + 8]
            if ctype == b"IHDR" and off + 8 + 13 <= len(data):
                w, h, depth, color = struct.unpack(
                    ">IIBB", data[off + 8 : off + 8 + 10]
                )
                self._prop(out, "png", "width", w)
                self._prop(out, "png", "height", h)
                self._prop(out, "png", "bit_depth", depth)
                cmap = {
                    0: "grayscale",
                    2: "RGB",
                    3: "palette",
                    4: "grayscale+alpha",
                    6: "RGBA",
                }
                self._prop(out, "png", "color_type", cmap.get(color, str(color)))
            if ctype == b"acTL":
                is_apng = True
                if off + 8 + 8 <= len(data):
                    nframes, nplays = struct.unpack(">II", data[off + 8 : off + 16])
                    self._prop(out, "png", "apng_frames", nframes)
            if ctype == b"IDAT" or ctype == b"IEND":
                break
            off += 12 + length
        if is_apng:
            out["format"] = "Animated PNG (APNG)"

    # ==================================================================
    # JPEG 2000
    # ==================================================================
    def _p_jp2(self, p, head, out):
        data = head
        out["family"] = "image"
        if data[:4] == b"\xff\x4f\xff\x51":
            out["format"] = "JPEG 2000 codestream (J2C)"
            # SIZ marker immediately follows SOC.
            if len(data) >= 40:
                xsiz, ysiz = struct.unpack(">II", data[8:16])
                x0, y0 = struct.unpack(">II", data[16:24])
                self._prop(out, "jp2", "width", xsiz - x0)
                self._prop(out, "jp2", "height", ysiz - y0)
        else:
            out["format"] = "JPEG 2000 (JP2)"
            boxes: List[Tuple[str, int, int]] = []
            self._iso_walk(data, 0, len(data), boxes, 0)
            for typ, o, s in boxes[:_MAX_BOXES]:
                out["sections"].append(self._sec(typ, "jp2-box", o, s))

    # ==================================================================
    # JPEG-XR / HD Photo / JPEG XL
    # ==================================================================
    def _p_jxr(self, p, head, out):
        out["family"] = "image"
        if head[:4] in (b"\x00\x00\x00\x0c",) and b"JXL " in head[:16]:
            out["format"] = "JPEG XL (container)"
        elif head[:2] == b"\xff\x0a":
            out["format"] = "JPEG XL (codestream)"
        else:
            out["format"] = "JPEG XR / HD Photo"
            self._prop(out, "jxr", "signature", "II" + hex(head[2]))

    def _p_jbig(self, p, head, out):
        out["family"] = "image"
        out["format"] = "JBIG2" if head[:4] == b"\x97JB2" else "JBIG bi-level image"

    # ==================================================================
    # OpenEXR / Radiance / PFM
    # ==================================================================
    def _p_exr(self, p, head, out):
        out["family"] = "image"
        if head[:4] == b"\x76\x2f\x31\x01":
            out["format"] = "OpenEXR (HDR)"
            self._prop(
                out,
                "exr",
                "version",
                struct.unpack("<I", head[4:8])[0] & 0xFF if len(head) >= 8 else 0,
            )
        else:
            out["format"] = "Radiance HDR (RGBE)"

    # ==================================================================
    # GPU / compressed textures
    # ==================================================================
    def _p_gpu(self, p, head, out):
        data = head
        out["family"] = "image"
        if data[:7] == b"\xabKTX 1":
            out["format"] = "Khronos Texture (KTX)"
            if len(data) >= 44:
                endian = "<" if data[12:16] == b"\x01\x02\x03\x04" else ">"
                w, h = struct.unpack(endian + "II", data[36:44])
                self._prop(out, "ktx", "width", w)
                self._prop(out, "ktx", "height", h)
        elif data[:7] == b"\xabKTX 2":
            out["format"] = "Khronos Texture 2 (KTX2)"
            if len(data) >= 44:
                vkfmt, ts, w, h = struct.unpack("<IIII", data[12:28])
                self._prop(out, "ktx2", "vk_format", vkfmt)
                self._prop(out, "ktx2", "width", w)
                self._prop(out, "ktx2", "height", h)
        elif data[:4] == b"\x13\xab\xa1\x5c":
            out["format"] = "ASTC compressed texture"
            bx, by = data[4], data[5]
            xs = data[7] | (data[8] << 8) | (data[9] << 16)
            ys = data[10] | (data[11] << 8) | (data[12] << 16)
            self._prop(out, "astc", "block", f"{bx}x{by}")
            self._prop(out, "astc", "width", xs)
            self._prop(out, "astc", "height", ys)
        elif data[:4] == b"DDS ":
            out["format"] = "DirectDraw Surface (DDS)"
            if len(data) >= 20:
                h, w = struct.unpack("<II", data[12:20])
                self._prop(out, "dds", "width", w)
                self._prop(out, "dds", "height", h)
        elif data[:3] == b"PVR" or data[44:48] == b"PVR!":
            out["format"] = "PowerVR texture (PVR)"
        else:
            out["format"] = "GPU compressed texture"

    # ==================================================================
    # Misc image headers (BPG / FLIF / farbfeld / PAM / WBMP)
    # ==================================================================
    def _p_image_hdr(self, p, head, out):
        data = head
        out["family"] = "image"
        if data[:4] == b"BPG\xfb":
            out["format"] = "BPG (Better Portable Graphics)"
        elif data[:4] == b"FLIF":
            out["format"] = "FLIF (Free Lossless Image Format)"
        elif data[:8] == b"farbfeld":
            out["format"] = "farbfeld image"
            if len(data) >= 16:
                w, h = struct.unpack(">II", data[8:16])
                self._prop(out, "farbfeld", "width", w)
                self._prop(out, "farbfeld", "height", h)
        else:
            out["format"] = "raster image"

    # ==================================================================
    # BMP / ICO / ICNS
    # ==================================================================
    def _p_bmp(self, p, head, out):
        data = head
        out["format"] = "BMP"
        out["family"] = "image"
        if len(data) >= 26:
            fsize = struct.unpack("<I", data[2:6])[0]
            hdr = struct.unpack("<I", data[14:18])[0]
            self._prop(out, "bmp", "file_size", fsize)
            self._prop(out, "bmp", "dib_header_size", hdr)
            if hdr >= 40 and len(data) >= 30:
                w, h = struct.unpack("<ii", data[18:26])
                bpp = struct.unpack("<H", data[28:30])[0]
                self._prop(out, "bmp", "width", w)
                self._prop(out, "bmp", "height", abs(h))
                self._prop(out, "bmp", "bits_per_pixel", bpp)

    def _p_ico(self, p, head, out):
        data = head
        typ = struct.unpack("<H", data[2:4])[0]
        out["format"] = "Windows cursor (CUR)" if typ == 2 else "Windows icon (ICO)"
        out["family"] = "image"
        n = struct.unpack("<H", data[4:6])[0]
        self._prop(out, "ico", "image_count", n)
        for i in range(min(n, 64)):
            base = 6 + i * 16
            if base + 16 > len(data):
                break
            w, h = data[base] or 256, data[base + 1] or 256
            out["sections"].append(self._sec(f"icon{i} {w}x{h}", "ico-entry", base, 16))

    def _p_icns(self, p, head, out):
        data = head
        out["format"] = "Apple Icon Image (ICNS)"
        out["family"] = "image"
        if len(data) >= 8:
            self._prop(out, "icns", "file_size", struct.unpack(">I", data[4:8])[0])
        off = 8
        while off + 8 <= len(data):
            typ = data[off : off + 4].decode("latin-1", "replace")
            size = struct.unpack(">I", data[off + 4 : off + 8])[0]
            if size < 8:
                break
            out["sections"].append(self._sec(typ, "icns-element", off, size))
            off += size

    # ==================================================================
    # GIF
    # ==================================================================
    def _p_gif(self, p, head, out):
        data = head
        out["format"] = "GIF"
        out["family"] = "image"
        self._prop(out, "gif", "version", data[:6].decode("latin-1", "replace"))
        if len(data) >= 10:
            w, h = struct.unpack("<HH", data[6:10])
            self._prop(out, "gif", "width", w)
            self._prop(out, "gif", "height", h)
        if b"NETSCAPE2.0" in data[:4096]:
            self._prop(out, "gif", "animated", "yes")
            out["format"] = "Animated GIF"

    # ==================================================================
    # Photoshop PSD / GIMP XCF
    # ==================================================================
    def _p_psd(self, p, head, out):
        data = head
        out["format"] = "Adobe Photoshop (PSD)"
        out["family"] = "image"
        if len(data) >= 26:
            sig, ver, _r, chans, h, w, depth, mode = struct.unpack(
                ">4sH6sHIIHH", data[:26]
            )
            if ver == 2:
                out["format"] = "Adobe Photoshop Big (PSB)"
            self._prop(out, "psd", "version", ver)
            self._prop(out, "psd", "channels", chans)
            self._prop(out, "psd", "width", w)
            self._prop(out, "psd", "height", h)
            self._prop(out, "psd", "depth", depth)
            modes = {
                0: "Bitmap",
                1: "Grayscale",
                2: "Indexed",
                3: "RGB",
                4: "CMYK",
                7: "Multichannel",
                8: "Duotone",
                9: "Lab",
            }
            self._prop(out, "psd", "color_mode", modes.get(mode, str(mode)))

    def _p_xcf(self, p, head, out):
        data = head
        out["format"] = "GIMP image (XCF)"
        out["family"] = "image"
        ver = data[9:13].rstrip(b"\x00").decode("latin-1", "replace")
        self._prop(out, "xcf", "version", ver or "v0")
        if len(data) >= 22:
            w, h = struct.unpack(">II", data[14:22])
            self._prop(out, "xcf", "width", w)
            self._prop(out, "xcf", "height", h)

    # ==================================================================
    # 3D: FBX / Blender / USDC / glTF-binary / OpenVDB
    # ==================================================================
    def _p_fbx(self, p, head, out):
        data = head
        out["format"] = "Autodesk FBX (binary)"
        out["family"] = "model"
        if len(data) >= 27:
            ver = struct.unpack("<I", data[23:27])[0]
            self._prop(out, "fbx", "version", ver)

    def _p_blend(self, p, head, out):
        data = head
        out["format"] = "Blender scene (.blend)"
        out["family"] = "model"
        if len(data) >= 12:
            ptr = "64-bit" if data[7:8] == b"-" else "32-bit"
            endian = "little" if data[8:9] == b"v" else "big"
            ver = data[9:12].decode("latin-1", "replace")
            self._prop(out, "blend", "pointer_size", ptr)
            self._prop(out, "blend", "endianness", endian)
            self._prop(out, "blend", "version", ver)

    def _p_usd(self, p, head, out):
        out["format"] = "Pixar USD (crate, .usdc)"
        out["family"] = "model"
        if len(head) >= 16:
            ver = head[8:16].rstrip(b"\x00")
            self._prop(out, "usd", "crate_version", ".".join(str(b) for b in ver[:3]))

    def _p_gltf(self, p, head, out):
        data = head
        out["format"] = "glTF binary (GLB)"
        out["family"] = "model"
        if len(data) >= 12:
            ver, total = struct.unpack("<II", data[4:12])
            self._prop(out, "glb", "version", ver)
            self._prop(out, "glb", "total_length", total)
        if len(data) >= 20:
            clen = struct.unpack("<I", data[12:16])[0]
            self._prop(out, "glb", "json_chunk_length", clen)

    def _p_openvdb(self, p, head, out):
        out["family"] = "model"
        if head[:7] == b"NanoVDB":
            out["format"] = "NanoVDB volume"
            return
        out["format"] = "OpenVDB volume"
        # 8-byte magic 0x2042445600000000 then uint32 file version and
        # library major/minor versions.
        if len(head) >= 20:
            file_ver = struct.unpack("<I", head[8:12])[0]
            lib_major, lib_minor = struct.unpack("<II", head[12:20])
            self._prop(out, "openvdb", "file_version", file_ver)
            self._prop(out, "openvdb", "library_version", f"{lib_major}.{lib_minor}")

    # ==================================================================
    # ZIP-based packages (OPC / ODF / bundles / app packages)
    # ==================================================================
    _ZIP_HINT = {
        ".pptx": "PowerPoint (OOXML)",
        ".xlsb": "Excel binary (OOXML)",
        ".docx": "Word (OOXML)",
        ".odp": "OpenDocument Presentation",
        ".odt": "OpenDocument Text",
        ".odg": "OpenDocument Graphics",
        ".numbers": "Apple Numbers",
        ".key": "Apple Keynote",
        ".pages": "Apple Pages",
        ".ipa": "iOS app package",
        ".aab": "Android App Bundle",
        ".apks": "Android APK set",
        ".xapk": "Android XAPK",
        ".appx": "Windows APPX",
        ".msix": "Windows MSIX",
        ".epub3": "EPUB 3 e-book",
        ".kra": "Krita image",
        ".sketch": "Sketch design",
        ".fig": "Figma export",
        ".glyphs": "Glyphs font source",
        ".ufo": "Unified Font Object",
        ".unitypackage": "Unity package",
        ".love": "LOVE2D game",
        ".3mf": "3D Manufacturing Format",
        ".conda": "Conda package",
        ".crx": "Chrome extension",
        ".pbix": "Power BI report",
    }

    def _p_zip(self, p, head, out):
        out["format"] = "ZIP-based package (OPC/ODF/bundle)"
        out["family"] = "container"
        ext = self._ext_of(p)
        if ext in self._ZIP_HINT:
            out["format"] = self._ZIP_HINT[ext] + " (ZIP)"
        try:
            import zipfile

            with zipfile.ZipFile(p) as zf:
                names = zf.namelist()
                self._prop(out, "zip", "member_count", len(names))
                total = sum(i.file_size for i in zf.infolist())
                comp = sum(i.compress_size for i in zf.infolist())
                self._prop(out, "zip", "uncompressed_size", total)
                self._prop(out, "zip", "compressed_size", comp)
                if total:
                    self._prop(out, "zip", "compression_ratio", round(comp / total, 4))
                # Package-type discriminators from well-known member names.
                markers = {
                    "[Content_Types].xml": "OPC (OOXML/XPS)",
                    "mimetype": "ODF/EPUB",
                    "AndroidManifest.xml": "Android package",
                    "Info.plist": "Apple bundle",
                    "META-INF/MANIFEST.MF": "Java/JAR-style",
                    "manifest.json": "extension/webext",
                }
                for m, label in markers.items():
                    if m in names or any(
                        n.endswith("/" + m) or n == m for n in names[:200]
                    ):
                        self._prop(out, "zip", "package_kind", label)
                        break
                # First-level entries as sections (bounded).
                seen = set()
                for i in zf.infolist():
                    top = i.filename.split("/")[0]
                    if top and top not in seen and len(seen) < 64:
                        seen.add(top)
                        out["sections"].append(
                            self._sec(top, "zip-entry", 0, i.file_size)
                        )
        except Exception as err:  # noqa: BLE001
            out["notes"] = f"zip read partial: {type(err).__name__}: {err}"

    # ==================================================================
    # gzip / ar / rpm / xar
    # ==================================================================
    def _p_gzip(self, p, head, out):
        data = head
        out["format"] = "gzip stream"
        out["family"] = "archive"
        if len(data) >= 10:
            flags = data[3]
            mtime = struct.unpack("<I", data[4:8])[0]
            self._prop(out, "gzip", "mtime", mtime)
            if flags & 0x08:  # FNAME present
                end = data.find(b"\x00", 10)
                if 10 < end < len(data):
                    self._prop(
                        out,
                        "gzip",
                        "original_name",
                        data[10:end].decode("latin-1", "replace"),
                    )

    def _p_ar(self, p, head, out):
        out["format"] = "Unix ar archive"
        out["family"] = "static-library"
        try:
            with open(p, "rb") as fh:
                fh.seek(8)
                first = fh.read(16).rstrip()
                if first == b"debian-binary":
                    out["format"] = "Debian package (.deb)"
                    out["family"] = "package"
        except OSError:
            pass

    def _p_rpm(self, p, head, out):
        data = head
        out["format"] = "RPM package"
        out["family"] = "package"
        if len(data) >= 10:
            major, minor = data[4], data[5]
            typ = struct.unpack(">H", data[6:8])[0]
            self._prop(out, "rpm", "version", f"{major}.{minor}")
            self._prop(out, "rpm", "type", "binary" if typ == 0 else "source")

    def _p_xar(self, p, head, out):
        data = head
        out["format"] = "XAR archive (.pkg/.xip)"
        out["family"] = "package"
        if len(data) >= 28:
            hsize, ver, toc_c, toc_u = struct.unpack(">HH", data[4:8]) + struct.unpack(
                ">QQ", data[8:24]
            )
            self._prop(out, "xar", "version", ver)
            self._prop(out, "xar", "toc_compressed", toc_c)
            self._prop(out, "xar", "toc_uncompressed", toc_u)

    def _p_generic_archive(self, p, head, out):
        fam = self._sniff(head)
        labels = {
            "sevenzip": "7-Zip archive",
            "rar": "RAR archive",
            "cab": "Microsoft Cabinet",
        }
        out["format"] = labels.get(fam, "archive")
        out["family"] = "archive"

    # ==================================================================
    # Disk & filesystem images
    # ==================================================================
    def _p_disk_vhd(self, p, head, out):
        out["family"] = "disk-image"
        if head[:8] == b"vhdxfile":
            out["format"] = "Hyper-V VHDX disk image"
            self._prop(out, "vhdx", "signature", "vhdxfile")
        else:
            out["format"] = "Virtual Hard Disk (VHD)"
            # Footer (512 bytes) carries 'conectix'; check the tail.
            foot = self._tail(p, 512)
            if foot[:8] == b"conectix" and len(foot) >= 0x55:
                self._prop(out, "vhd", "cookie", "conectix")
                self._prop(
                    out,
                    "vhd",
                    "creator_app",
                    foot[0x1C:0x20].decode("latin-1", "replace").strip(),
                )
                cver = struct.unpack(">HH", foot[0x20:0x24])
                self._prop(out, "vhd", "creator_version", f"{cver[0]}.{cver[1]}")
                self._prop(
                    out,
                    "vhd",
                    "creator_host_os",
                    foot[0x24:0x28].decode("latin-1", "replace").strip(),
                )
                orig = struct.unpack(">Q", foot[0x28:0x30])[0]
                cur = struct.unpack(">Q", foot[0x30:0x38])[0]
                self._prop(out, "vhd", "original_size", orig)
                self._prop(out, "vhd", "current_size", cur)
                cyl, heads, spt = struct.unpack(">HBB", foot[0x38:0x3C])
                self._prop(out, "vhd", "geometry", f"{cyl}C/{heads}H/{spt}S")
                dtype = struct.unpack(">I", foot[0x3C:0x40])[0]
                self._prop(
                    out, "vhd", "disk_type", self._VHD_TYPE.get(dtype, f"type {dtype}")
                )

    def _p_disk_vmdk(self, p, head, out):
        out["family"] = "disk-image"
        out["format"] = "VMware VMDK disk image"
        if head[:4] == b"KDMV" and len(head) >= 0x40:
            ver = struct.unpack("<I", head[4:8])[0]
            self._prop(out, "vmdk", "kind", "sparse")
            self._prop(out, "vmdk", "version", ver)
            flags = struct.unpack("<I", head[8:12])[0]
            cap, grain = struct.unpack("<QQ", head[12:28])
            self._prop(out, "vmdk", "flags", hex(flags))
            self._prop(out, "vmdk", "capacity_sectors", cap)
            self._prop(out, "vmdk", "capacity_bytes", cap * 512)
            self._prop(out, "vmdk", "grain_size_sectors", grain)
        else:
            self._prop(out, "vmdk", "kind", "descriptor")

    def _p_disk_vdi(self, p, head, out):
        out["family"] = "disk-image"
        out["format"] = "VirtualBox VDI disk image"
        # VDI pre-header: 64-byte text signature then <I magic (0xBEDA107F) @0x40.
        if len(head) >= 0x180 and struct.unpack("<I", head[0x40:0x44])[0] == 0xBEDA107F:
            ver = struct.unpack("<HH", head[0x44:0x48])
            self._prop(out, "vdi", "version", f"{ver[1]}.{ver[0]}")
            itype = struct.unpack("<I", head[0x4C:0x50])[0]
            self._prop(
                out,
                "vdi",
                "image_type",
                {1: "dynamic", 2: "fixed", 4: "undo", 5: "diff"}.get(itype, str(itype)),
            )
            block_size = struct.unpack("<I", head[0x150:0x154])[0]
            disk_size = struct.unpack("<Q", head[0x170:0x178])[0]
            blocks = struct.unpack("<I", head[0x158:0x15C])[0]
            self._prop(out, "vdi", "disk_size", disk_size)
            self._prop(out, "vdi", "block_size", block_size)
            self._prop(out, "vdi", "blocks_in_image", blocks)

    def _p_disk_qcow(self, p, head, out):
        out["family"] = "disk-image"
        # QED (QEMU Enhanced Disk) shares the family/ext space with QCOW.
        if head[:4] == b"QED\x00" and len(head) >= 0x38:
            out["format"] = "QEMU Enhanced Disk (QED)"
            # QED header: cluster_size @0x04, table_size @0x08, header_size @0x0c
            # (both in clusters), features @0x10, image_size (bytes) @0x30.
            cluster, table, hsize = struct.unpack("<III", head[0x04:0x10])
            features = struct.unpack("<Q", head[0x10:0x18])[0]
            img = struct.unpack("<Q", head[0x30:0x38])[0]
            self._prop(out, "qed", "cluster_size", cluster)
            self._prop(out, "qed", "table_size_clusters", table)
            self._prop(out, "qed", "header_size_clusters", hsize)
            self._prop(out, "qed", "features", hex(features))
            self._prop(out, "qed", "image_size", img)
            return
        out["format"] = "QEMU QCOW disk image"
        if head[:4] == b"QFI\xfb" and len(head) >= 24:
            ver = struct.unpack(">I", head[4:8])[0]
            self._prop(out, "qcow", "version", ver)
            out["format"] = f"QEMU QCOW{ver} disk image"
            bf_off, bf_size = struct.unpack(">QI", head[8:20])
            if bf_off:
                self._prop(out, "qcow", "has_backing_file", True)
                bf = self._read_at(p, head, bf_off, min(bf_size, 4096))
                if bf:
                    self._prop(
                        out, "qcow", "backing_file", bf.decode("utf-8", "replace")
                    )
            cbits = struct.unpack(">I", head[20:24])[0]
            self._prop(
                out, "qcow", "cluster_size", 1 << cbits if 0 < cbits < 40 else None
            )
            size = struct.unpack(">Q", head[24:32])[0] if len(head) >= 32 else None
            if size:
                self._prop(out, "qcow", "virtual_size", size)
            if len(head) >= 40:
                crypt = struct.unpack(">I", head[32:36])[0]
                self._prop(
                    out,
                    "qcow",
                    "crypt_method",
                    {0: "none", 1: "AES", 2: "LUKS"}.get(crypt, str(crypt)),
                )
                nsnap = struct.unpack(">I", head[60:64])[0] if len(head) >= 64 else 0
                self._prop(out, "qcow", "snapshot_count", nsnap)

    def _p_disk_iso(self, p, head, out):
        out["family"] = "disk-image"
        out["format"] = "Optical disc image"
        ext = self._ext_of(p)
        labels = {
            ".cso": "Compressed ISO (CISO)",
            ".rvz": "Dolphin RVZ image",
            ".wbfs": "Wii WBFS image",
            ".gcm": "GameCube disc image",
            ".nrg": "Nero disc image",
        }
        if ext in labels:
            out["format"] = labels[ext]
        # ISO9660 Primary Volume Descriptor: 'CD001' at 0x8001 (type byte 0x8000==1).
        pvd = self._read_at(p, head, 0x8000, 2048)
        if len(pvd) >= 0x578 and pvd[1:6] == b"CD001" and pvd[0] == 1:
            out["format"] = "ISO 9660 filesystem image"
            self._prop(out, "iso9660", "standard_id", "CD001")
            self._prop(
                out,
                "iso9660",
                "system_id",
                pvd[8:40].decode("latin-1", "replace").strip(),
            )
            self._prop(
                out,
                "iso9660",
                "volume_id",
                pvd[40:72].decode("latin-1", "replace").strip(),
            )
            # Volume space size + logical block size are both-endian; take LE halves.
            space = struct.unpack("<I", pvd[80:84])[0]
            lbs = struct.unpack("<H", pvd[128:130])[0]
            self._prop(out, "iso9660", "logical_block_size", lbs)
            self._prop(out, "iso9660", "volume_space_size", space)
            if lbs:
                self._prop(out, "iso9660", "volume_size_bytes", space * lbs)

    def _p_disk_dmg(self, p, head, out):
        out["family"] = "disk-image"
        out["format"] = "Apple Disk Image (DMG)"
        foot = self._tail(p, 512)
        if foot[-512:][:4] == b"koly" or foot[:4] == b"koly":
            self._prop(out, "dmg", "trailer", "koly")

    def _p_disk_wim(self, p, head, out):
        out["family"] = "disk-image"
        out["format"] = "Windows Imaging Format (WIM)"
        if len(head) >= 0x18:
            ver = struct.unpack("<I", head[0x18:0x1C])[0] if len(head) >= 0x1C else None
            if ver:
                self._prop(out, "wim", "version", hex(ver))

    def _p_disk_squashfs(self, p, head, out):
        out["family"] = "disk-image"
        ext = self._ext_of(p)
        out["format"] = {
            ".snap": "Snap package (SquashFS)",
            ".sif": "Singularity/Apptainer image",
            ".appimage": "AppImage (SquashFS payload)",
        }.get(ext, "SquashFS filesystem")
        if head[:4] in (b"hsqs", b"sqsh"):
            endian = "<" if head[:4] == b"hsqs" else ">"
            if len(head) >= 32:
                inodes = struct.unpack(endian + "I", head[4:8])[0]
                self._prop(out, "squashfs", "inode_count", inodes)
                block_size = struct.unpack(endian + "I", head[12:16])[0]
                comp = struct.unpack(endian + "H", head[20:22])[0]
                vmaj, vmin = struct.unpack(endian + "HH", head[28:32])
                self._prop(out, "squashfs", "version", f"{vmaj}.{vmin}")
                self._prop(out, "squashfs", "block_size", block_size)
                self._prop(
                    out,
                    "squashfs",
                    "compression",
                    self._SQFS_COMP.get(comp, f"id {comp}"),
                )

    def _p_disk_generic(self, p, head, out):
        out["family"] = "disk-image"
        if head[:8] == b"EVF\x09\x0d\x0a\xff\x00":
            out["format"] = "EnCase/EWF forensic image (E01)"
        else:
            out["format"] = "raw disk / forensic image"

    def _p_fs_super(self, p, head, out):
        out["family"] = "filesystem"
        ext = self._ext_of(p)
        labels = {
            ".ext4": "ext2/3/4 filesystem",
            ".btrfs": "Btrfs filesystem",
            ".xfs": "XFS filesystem",
            ".ntfs": "NTFS filesystem",
            ".fat": "FAT filesystem",
            ".exfat": "exFAT filesystem",
            ".hfsplus": "HFS+ filesystem",
            ".apfs": "APFS container",
            ".cramfs": "cramfs filesystem",
            ".romfs": "romfs filesystem",
            ".jffs2": "JFFS2 flash filesystem",
            ".ubifs": "UBIFS flash filesystem",
            ".erofs": "EROFS filesystem",
            ".zfs": "ZFS pool",
            ".littlefs": "littlefs flash filesystem",
            ".spiffs": "SPIFFS flash filesystem",
        }
        out["format"] = labels.get(ext, "filesystem image")
        if head[:8] == b"-rom1fs-":
            out["format"] = "romfs filesystem"
            if len(head) >= 16:
                self._prop(out, "romfs", "size", struct.unpack(">I", head[8:12])[0])
        # ext superblock magic 0xEF53 at 0x438.
        try:
            with open(p, "rb") as fh:
                fh.seek(0x438)
                if fh.read(2) == b"\x53\xef":
                    out["format"] = "ext2/3/4 filesystem"
                    self._prop(out, "extfs", "magic", "0xEF53")
        except OSError:
            pass

    # ==================================================================
    # Certificates / keys (ASN.1 DER) & keystores
    # ==================================================================
    def _p_der(self, p, head, out):
        data = head
        out["family"] = "certificate"
        out["format"] = "ASN.1 DER (X.509/PKCS)"
        ext = self._ext_of(p)
        labels = {
            ".cer": "X.509 certificate",
            ".crt": "X.509 certificate",
            ".der": "DER-encoded object",
            ".crl": "certificate revocation list",
            ".p7b": "PKCS#7 cert bundle",
            ".p7c": "PKCS#7 certificate",
            ".p7m": "PKCS#7 signed/enveloped (S/MIME)",
            ".p7s": "PKCS#7 signature",
            ".pfx": "PKCS#12 keystore",
            ".p12": "PKCS#12 keystore",
            ".cades": "CAdES advanced signature",
            ".mobileprovision": "Apple provisioning profile (CMS)",
            ".cat": "Windows security catalog (PKCS#7)",
        }
        if ext in labels:
            out["format"] = labels[ext]
        # Parse the outer SEQUENCE length.
        if data[:1] == b"\x30":
            b1 = data[1]
            if b1 & 0x80:
                nlen = b1 & 0x7F
                if 0 < nlen <= 4 and len(data) >= 2 + nlen:
                    total = int.from_bytes(data[2 : 2 + nlen], "big")
                    self._prop(out, "asn1", "sequence_length", total)
            self._prop(out, "asn1", "outer_tag", "SEQUENCE")

    def _p_keystore(self, p, head, out):
        data = head
        out["family"] = "certificate"
        ext = self._ext_of(p)
        if data[:4] == b"\xfe\xed\xfe\xed":
            out["format"] = "Java KeyStore (JKS)"
            if len(data) >= 8:
                self._prop(out, "jks", "version", struct.unpack(">I", data[4:8])[0])
        elif ext == ".ppk":
            out["format"] = "PuTTY private key (PPK)"
        else:
            out["format"] = "keystore / encrypted key container"

    # ==================================================================
    # Scientific containers: HDF5 / HDF4 / NetCDF / GRIB / FITS / MATLAB / NPY
    # ==================================================================
    def _p_hdf5(self, p, head, out):
        out["family"] = "scientific"
        out["format"] = "HDF5 container"
        ext = self._ext_of(p)
        labels = {
            ".mat73": "MATLAB v7.3 (HDF5)",
            ".nwb": "Neurodata NWB (HDF5)",
            ".cool": "cooler Hi-C (HDF5)",
            ".mcool": "multi-res cooler (HDF5)",
            ".gii": "GIFTI surface (HDF5/XML)",
            ".cifti": "CIFTI connectivity",
            ".weights.h5": "Keras weights (HDF5)",
            ".qvd": "QlikView data (HDF5-like)",
        }
        if ext in labels:
            out["format"] = labels[ext]
        if len(head) >= 9:
            self._prop(out, "hdf5", "superblock_version", head[8])

    def _p_hdf4(self, p, head, out):
        out["family"] = "scientific"
        out["format"] = "HDF4 container"

    def _p_netcdf(self, p, head, out):
        out["family"] = "scientific"
        ver = head[3] if len(head) >= 4 else 0
        out["format"] = f"NetCDF classic (v{ver})"
        if len(head) >= 8:
            self._prop(out, "netcdf", "numrecs", struct.unpack(">I", head[4:8])[0])

    def _p_grib(self, p, head, out):
        out["family"] = "scientific"
        out["format"] = "GRIB gridded data"
        if len(head) >= 8:
            self._prop(out, "grib", "edition", head[7])

    def _p_fits(self, p, head, out):
        out["family"] = "scientific"
        out["format"] = "FITS (astronomy)"
        # 80-char header cards; read a few keywords.
        text = head[:2880].decode("latin-1", "replace")
        for kw in ("BITPIX", "NAXIS", "NAXIS1", "NAXIS2"):
            i = text.find(kw)
            if i >= 0:
                seg = text[i : i + 30]
                eq = seg.find("=")
                if eq >= 0:
                    self._prop(out, "fits", kw.lower(), seg[eq + 1 : eq + 21].strip())

    def _p_matlab(self, p, head, out):
        out["family"] = "scientific"
        out["format"] = "MATLAB MAT-file (v5)"
        desc = head[:116].split(b"\x00")[0].decode("latin-1", "replace").strip()
        if desc:
            self._prop(out, "matlab", "description", desc[:120])
        if len(head) >= 128:
            ver, endian = struct.unpack("<H2s", head[124:128])
            self._prop(out, "matlab", "version", hex(ver))

    def _p_npy(self, p, head, out):
        out["family"] = "scientific"
        out["format"] = "NumPy .npy array"
        if len(head) >= 10:
            major, minor = head[6], head[7]
            hlen = struct.unpack("<H", head[8:10])[0]
            hdr = head[10 : 10 + hlen].decode("latin-1", "replace")
            self._prop(out, "npy", "version", f"{major}.{minor}")
            for key in ("descr", "fortran_order", "shape"):
                i = hdr.find("'" + key + "'")
                if i >= 0:
                    self._prop(
                        out,
                        "npy",
                        key,
                        hdr[i : i + 60].split(":", 1)[-1].split(",", 1)[0].strip(" '"),
                    )

    # ==================================================================
    # ML model containers (GGUF / GGML / TFLite)
    # ==================================================================
    def _p_gguf(self, p, head, out):
        data = head
        out["family"] = "model"
        if data[:4] == b"GGUF":
            out["format"] = "GGUF model (llama.cpp)"
            if len(data) >= 24:
                ver = struct.unpack("<I", data[4:8])[0]
                ntensors = struct.unpack("<Q", data[8:16])[0]
                nkv = struct.unpack("<Q", data[16:24])[0]
                self._prop(out, "gguf", "version", ver)
                self._prop(out, "gguf", "tensor_count", ntensors)
                self._prop(out, "gguf", "metadata_kv_count", nkv)
        else:
            magic = data[:4].decode("latin-1", "replace")
            out["format"] = f"GGML-family model ({magic})"

    def _p_tflite(self, p, head, out):
        out["family"] = "model"
        out["format"] = "TensorFlow Lite (FlatBuffer)"
        self._prop(out, "tflite", "identifier", "TFL3")

    # ==================================================================
    # Serialization wire formats
    # ==================================================================
    def _p_ion(self, p, head, out):
        out["family"] = "serialization"
        out["format"] = "Amazon Ion (binary)"
        self._prop(out, "ion", "bvm", "E00100EA")

    def _p_smile(self, p, head, out):
        out["family"] = "serialization"
        out["format"] = "Smile (binary JSON)"

    def _p_marshal(self, p, head, out):
        out["family"] = "serialization"
        out["format"] = "Ruby Marshal"
        if len(head) >= 2:
            self._prop(out, "marshal", "version", f"{head[0]}.{head[1]}")

    def _p_magicless_serial(self, p, head, out):
        fam = self.family_for(p.name) or "serialization"
        labels = {
            "msgpack": "MessagePack",
            "cbor": "CBOR",
            "ubjson": "UBJSON",
            "bson": "BSON",
            "flatbuffers": "FlatBuffers",
            "protobuf": "Protocol Buffers",
            "recordio": "record/tensor stream",
        }
        out["family"] = "serialization"
        out["format"] = labels.get(fam, "binary serialization")
        # BSON: leading int32 document length.
        if fam == "bson" and len(head) >= 4:
            self._prop(
                out, "bson", "first_document_length", struct.unpack("<i", head[:4])[0]
            )
        # IDX (MNIST-style): magic 0x00 0x00 type dims.
        if fam == "recordio" and head[:2] == b"\x00\x00" and len(head) >= 4:
            dtype = {
                0x08: "uint8",
                0x09: "int8",
                0x0B: "int16",
                0x0C: "int32",
                0x0D: "float32",
                0x0E: "float64",
            }.get(head[2])
            ndim = head[3]
            if dtype and 0 < ndim <= 4:
                out["format"] = "IDX tensor (MNIST-style)"
                self._prop(out, "idx", "dtype", dtype)
                self._prop(out, "idx", "dimensions", ndim)
                dims = []
                for d in range(ndim):
                    if 4 + d * 4 + 4 <= len(head):
                        dims.append(struct.unpack(">I", head[4 + d * 4 : 8 + d * 4])[0])
                if dims:
                    self._prop(out, "idx", "shape", "x".join(str(x) for x in dims))

    # ==================================================================
    # Fonts
    # ==================================================================
    _SFNT_VER = {
        b"\x00\x01\x00\x00": "TrueType",
        b"OTTO": "OpenType (CFF)",
        b"true": "TrueType (Apple)",
        b"typ1": "Type 1 (sfnt)",
        b"ttcf": "TrueType Collection",
    }

    # fsType embedding-permission bits (OS/2 table).
    _FSTYPE = {
        0x0000: "installable",
        0x0002: "restricted",
        0x0004: "preview & print",
        0x0008: "editable",
        0x0100: "no subsetting",
        0x0200: "bitmap embedding only",
    }

    def _p_sfnt(self, p, head, out):
        data = head
        out["family"] = "font"
        tag = data[:4]
        out["format"] = self._SFNT_VER.get(tag, "SFNT font")
        if tag == b"ttcf":
            if len(data) >= 12:
                nfonts = struct.unpack(">I", data[8:12])[0]
                self._prop(out, "font", "collection_count", nfonts)
            return
        if len(data) < 12:
            return
        num_tables = struct.unpack(">H", data[4:6])[0]
        self._prop(out, "font", "table_count", num_tables)
        # Table directory -> {tag: (offset, length)} + sections.
        tdir: Dict[str, Tuple[int, int]] = {}
        for i in range(min(num_tables, 64)):
            base = 12 + i * 16
            if base + 16 > len(data):
                break
            t = data[base : base + 4].decode("latin-1", "replace")
            off = struct.unpack(">I", data[base + 8 : base + 12])[0]
            length = struct.unpack(">I", data[base + 12 : base + 16])[0]
            tdir[t] = (off, length)
            out["sections"].append(self._sec(t, "sfnt-table", off, length))
        if "CFF " in tdir:
            self._prop(out, "font", "outline_type", "CFF/PostScript")
        elif "glyf" in tdir:
            self._prop(out, "font", "outline_type", "TrueType")

        # --- head: units per em, bounding box, style, loca format ---
        if "head" in tdir:
            hb = self._read_at(p, data, tdir["head"][0], 54)
            if (
                len(hb) >= 54 and hb[12:16] == b"\x5f\x0f\x3c\xf5"
            ):  # magicNumber verifies head
                rev = struct.unpack(">I", hb[4:8])[0] / 65536.0
                upm = struct.unpack(">H", hb[18:20])[0]
                xmin, ymin, xmax, ymax = struct.unpack(">hhhh", hb[36:44])
                mac_style = struct.unpack(">H", hb[44:46])[0]
                loca_fmt = struct.unpack(">h", hb[50:52])[0]
                self._prop(out, "font", "font_revision", round(rev, 3))
                self._prop(out, "font", "units_per_em", upm)
                self._prop(out, "font", "bbox", f"{xmin},{ymin},{xmax},{ymax}")
                styles = [
                    n
                    for b, n in (
                        (0x1, "bold"),
                        (0x2, "italic"),
                        (0x4, "underline"),
                        (0x20, "outline"),
                    )
                    if mac_style & b
                ]
                if styles:
                    self._prop(out, "font", "mac_style", ",".join(styles))
                self._prop(out, "font", "loca_format", "long" if loca_fmt else "short")

        # --- maxp: glyph count ---
        if "maxp" in tdir:
            mb = self._read_at(p, data, tdir["maxp"][0], 6)
            if len(mb) >= 6:
                self._prop(out, "font", "glyph_count", struct.unpack(">H", mb[4:6])[0])

        # --- hhea: vertical metrics + hmetric count ---
        if "hhea" in tdir:
            ab = self._read_at(p, data, tdir["hhea"][0], 36)
            if len(ab) >= 36:
                ascender, descender, line_gap = struct.unpack(">hhh", ab[4:10])
                num_hmetrics = struct.unpack(">H", ab[34:36])[0]
                self._prop(out, "font", "ascender", ascender)
                self._prop(out, "font", "descender", descender)
                self._prop(out, "font", "line_gap", line_gap)
                self._prop(out, "font", "hmetric_count", num_hmetrics)

        # --- OS/2: weight/width class, embedding permission, vendor ---
        if "OS/2" in tdir:
            ob = self._read_at(p, data, tdir["OS/2"][0], 64)
            if len(ob) >= 10:
                weight, width, fstype = struct.unpack(">HHH", ob[4:10])
                self._prop(out, "font", "weight_class", weight)
                self._prop(out, "font", "width_class", width)
                self._prop(
                    out,
                    "font",
                    "embedding",
                    self._FSTYPE.get(fstype & 0x030E, f"0x{fstype:04x}"),
                )
            if len(ob) >= 62:
                vendor = ob[58:62].decode("latin-1", "replace").strip("\x00 ")
                if vendor:
                    self._prop(out, "font", "vendor_id", vendor)

        # --- name: family / subfamily / full name / version ---
        if "name" in tdir:
            self._sfnt_names(p, data, tdir["name"][0], out)

        # --- cmap: encoding subtable coverage ---
        if "cmap" in tdir:
            cb = self._read_at(p, data, tdir["cmap"][0], 4)
            if len(cb) >= 4:
                ntab = struct.unpack(">H", cb[2:4])[0]
                recs = self._read_at(p, data, tdir["cmap"][0] + 4, min(ntab, 32) * 8)
                plats = set()
                for i in range(min(ntab, 32)):
                    if i * 8 + 4 <= len(recs):
                        pid, eid = struct.unpack(">HH", recs[i * 8 : i * 8 + 4])
                        plats.add(f"{pid}/{eid}")
                self._prop(out, "font", "cmap_subtables", ntab)
                if "3/10" in plats:
                    self._prop(out, "font", "unicode_coverage", "full (UCS-4)")
                elif "3/1" in plats or "0/3" in plats:
                    self._prop(out, "font", "unicode_coverage", "BMP")

    def _sfnt_names(self, p, head, name_off, out):
        """Decode the sfnt 'name' table for the common human-readable name IDs."""
        hdr = self._read_at(p, head, name_off, 6)
        if len(hdr) < 6:
            return
        count = struct.unpack(">H", hdr[2:4])[0]
        storage = struct.unpack(">H", hdr[4:6])[0]
        recs = self._read_at(p, head, name_off + 6, min(count, 128) * 12)
        wanted = {
            1: "family",
            2: "subfamily",
            4: "full_name",
            5: "version_string",
            6: "postscript_name",
        }
        seen = {}
        for i in range(min(count, 128)):
            r = recs[i * 12 : i * 12 + 12]
            if len(r) < 12:
                break
            pid, eid, lid, nid, ln, off = struct.unpack(">HHHHHH", r)
            if nid not in wanted or nid in seen:
                continue
            raw = self._read_at(p, head, name_off + storage + off, ln)
            if not raw:
                continue
            try:
                if pid == 3 or (pid == 0):  # Windows / Unicode -> UTF-16BE
                    txt = raw.decode("utf-16-be", "replace")
                else:  # Macintosh -> latin-1 approximation
                    txt = raw.decode("latin-1", "replace")
            except Exception:  # noqa: BLE001
                continue
            txt = txt.strip("\x00 ").replace("\x00", "")
            if txt:
                seen[nid] = txt
                self._prop(out, "font", wanted[nid], txt[:120])

    def _p_woff(self, p, head, out):
        data = head
        out["family"] = "font"
        out["format"] = "WOFF web font"
        if len(data) >= 44:
            flavor = data[4:8]
            num_tables = struct.unpack(">H", data[12:14])[0]
            total = struct.unpack(">I", data[16:20])[0]
            self._prop(out, "woff", "flavor", flavor.decode("latin-1", "replace"))
            self._prop(out, "woff", "table_count", num_tables)
            self._prop(out, "woff", "total_sfnt_size", total)

    def _p_woff2(self, p, head, out):
        data = head
        out["family"] = "font"
        out["format"] = "WOFF2 web font"
        if len(data) >= 48:
            num_tables = struct.unpack(">H", data[12:14])[0]
            total = struct.unpack(">I", data[16:20])[0]
            self._prop(out, "woff2", "table_count", num_tables)
            self._prop(out, "woff2", "total_sfnt_size", total)

    def _p_eot(self, p, head, out):
        data = head
        out["family"] = "font"
        out["format"] = "Embedded OpenType (EOT)"
        if len(data) >= 16:
            eot_size, font_size, ver = struct.unpack("<III", data[:12])
            self._prop(out, "eot", "font_data_size", font_size)
            self._prop(out, "eot", "version", hex(ver))

    def _p_type1(self, p, head, out):
        out["family"] = "font"
        out["format"] = "PostScript Type 1 (PFB)"
        if len(head) >= 6 and head[0] == 0x80:
            self._prop(
                out,
                "pfb",
                "first_segment_type",
                {1: "ASCII", 2: "binary", 3: "EOF"}.get(head[1], str(head[1])),
            )

    # ==================================================================
    # Documents
    # ==================================================================
    def _p_dvi(self, p, head, out):
        out["family"] = "document"
        out["format"] = "TeX DVI"
        if len(head) >= 3:
            self._prop(out, "dvi", "id_byte", head[2])

    def _p_djvu(self, p, head, out):
        out["family"] = "document"
        out["format"] = "DjVu document"
        # AT&TFORM then a 4-byte length then the form type.
        if len(head) >= 16:
            form = head[12:16].decode("latin-1", "replace")
            kinds = {
                "DJVU": "single page",
                "DJVM": "multi-page",
                "DJVI": "shared",
                "THUM": "thumbnails",
            }
            self._prop(out, "djvu", "form_type", kinds.get(form, form))

    def _p_pdf(self, p, head, out):
        out["family"] = "document"
        ext = self._ext_of(p)
        if ext in (".xps", ".oxps"):
            out["format"] = "XML Paper Specification (XPS)"
            out["family"] = "document"
            # XPS is a ZIP/OPC package.
            if head[:2] == b"PK":
                return self._p_zip(p, head, out)
            return
        out["format"] = "PDF/A document" if ext == ".pdfa" else "PDF document"
        ver = head[5:8].decode("latin-1", "replace")
        self._prop(out, "pdf", "version", ver)

    def _p_pcl(self, p, head, out):
        out["family"] = "document"
        ext = self._ext_of(p)
        out["format"] = {
            ".pwg": "PWG Raster",
            ".urf": "Apple URF Raster",
            ".ppf": "Print Production Format",
        }.get(ext, "PCL printer stream")
        if head[:1] == b"\x1b":
            self._prop(out, "pcl", "escape_prefix", "yes")

    # ==================================================================
    # Game ROM cartridge / container headers
    # ==================================================================
    def _p_rom_nes(self, p, head, out):
        out["family"] = "rom"
        out["format"] = "NES ROM (iNES)"
        if len(head) >= 8:
            prg, chr_ = head[4], head[5]
            f6, f7 = head[6], head[7]
            self._prop(out, "nes", "prg_rom_16kb_banks", prg)
            self._prop(out, "nes", "chr_rom_8kb_banks", chr_)
            self._prop(out, "nes", "mapper", (f6 >> 4) | (f7 & 0xF0))
            self._prop(
                out,
                "nes",
                "mirroring",
                (
                    "four-screen"
                    if f6 & 0x08
                    else ("vertical" if f6 & 0x01 else "horizontal")
                ),
            )
            if f6 & 0x02:
                self._prop(out, "nes", "battery_backed_ram", "yes")
            if f6 & 0x04:
                self._prop(out, "nes", "trainer", "yes (512-byte)")
            is_nes2 = head[:4] == b"NES\x1a" and (f7 & 0x0C) == 0x08
            if is_nes2 and len(head) >= 12:
                out["format"] = "NES ROM (NES 2.0)"
                self._prop(out, "nes", "mapper_high", head[8] & 0x0F)
                self._prop(out, "nes", "submapper", head[8] >> 4)
                self._prop(out, "nes", "prg_ram_shift", head[10] & 0x0F)
                self._prop(out, "nes", "chr_ram_shift", head[11] & 0x0F)
            else:
                self._prop(out, "nes", "tv_system", "PAL" if f7 & 0x01 else "NTSC")

    def _p_rom_n64(self, p, head, out):
        out["family"] = "rom"
        bo = {
            b"\x80\x37\x12\x40": ("Z64 (big-endian)", "z64"),
            b"\x37\x80\x40\x12": ("V64 (byte-swapped)", "v64"),
            b"\x40\x12\x37\x80": ("N64 (little-endian)", "n64"),
        }
        label, tag = bo.get(head[:4], ("Nintendo 64 ROM", "n64"))
        out["format"] = f"Nintendo 64 ROM ({label})"
        self._prop(out, "n64", "byte_order", tag)
        if len(head) >= 0x34:
            title = head[0x20:0x34].rstrip(b"\x00 ").decode("latin-1", "replace")
            self._prop(out, "n64", "internal_title", title)

    _SNES_MAP = {
        0x20: "LoROM",
        0x21: "HiROM",
        0x23: "SA-1",
        0x30: "LoROM+FastROM",
        0x31: "HiROM+FastROM",
        0x32: "ExLoROM",
        0x35: "ExHiROM",
    }
    _SNES_COUNTRY = {
        0x00: "Japan",
        0x01: "USA",
        0x02: "Europe",
        0x03: "Sweden",
        0x06: "France",
        0x07: "Netherlands",
        0x08: "Spain",
        0x09: "Germany",
        0x0B: "Italy",
        0x0C: "China",
        0x0E: "Korea",
        0x0F: "Canada",
    }
    _VHD_TYPE = {0: "none", 2: "fixed", 3: "dynamic", 4: "differencing"}
    _SQFS_COMP = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}

    def _p_rom_snes(self, p, head, out):
        out["family"] = "rom"
        out["format"] = "Super Nintendo ROM (SNES)"
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        skip = 512 if size % 1024 == 512 else 0
        self._prop(out, "snes", "copier_header", "yes" if skip else "no")
        # The internal header sits at 0x7FC0 (LoROM) or 0xFFC0 (HiROM); pick the
        # one whose checksum + complement == 0xFFFF (the documented validity test).
        best = None
        for loc, kind in ((0x7FC0, "LoROM"), (0xFFC0, "HiROM")):
            hb = self._read_at(p, head, loc + skip, 32)
            if len(hb) < 32:
                continue
            chk = struct.unpack("<H", hb[28:30])[0]
            cmp = struct.unpack("<H", hb[30:32])[0]
            score = 2 if (chk ^ cmp) == 0xFFFF else (1 if 0x20 <= hb[21] <= 0x3F else 0)
            if best is None or score > best[0]:
                best = (score, hb, kind)
        if best and best[0] > 0:
            hb, kind = best[1], best[2]
            title = hb[0x00:0x15].rstrip(b"\x00 ").decode("latin-1", "replace")
            map_mode = hb[0x15]
            rom_type = hb[0x16]
            rom_kib = (1 << hb[0x17]) if hb[0x17] < 20 else None
            sram_kib = (1 << hb[0x18]) if 0 < hb[0x18] < 20 else 0
            country = hb[0x19]
            ver = hb[0x1B]
            if title:
                self._prop(out, "snes", "title", title)
            self._prop(
                out,
                "snes",
                "map_mode",
                self._SNES_MAP.get(map_mode, hex(map_mode)) + f" ({kind})",
            )
            self._prop(out, "snes", "rom_type", hex(rom_type))
            if rom_kib:
                self._prop(out, "snes", "rom_size_kib", rom_kib)
            self._prop(out, "snes", "sram_size_kib", sram_kib)
            self._prop(
                out, "snes", "region", self._SNES_COUNTRY.get(country, hex(country))
            )
            self._prop(out, "snes", "version", f"1.{ver}")

    _GB_CART = {
        0x00: "ROM only",
        0x01: "MBC1",
        0x03: "MBC1+RAM+battery",
        0x05: "MBC2",
        0x0F: "MBC3+timer+battery",
        0x13: "MBC3+RAM+battery",
        0x19: "MBC5",
        0x1B: "MBC5+RAM+battery",
        0x1E: "MBC5+rumble+RAM+battery",
        0x20: "MBC6",
        0x22: "MBC7+sensor+rumble+RAM+battery",
        0xFC: "POCKET CAMERA",
        0xFF: "HuC1+RAM+battery",
    }
    _GB_RAM = {0x00: 0, 0x01: 2, 0x02: 8, 0x03: 32, 0x04: 128, 0x05: 64}
    _GB_LOGO = bytes.fromhex(
        "ceed6666cc0d000b03730083000c000d0008111f8889000edccc6ee6ddddd999bbbb67636e0eecccdddc999fbbb9333e"
    )

    def _p_rom_gb(self, p, head, out):
        out["family"] = "rom"
        out["format"] = "Game Boy ROM"
        if len(head) < 0x150:
            return
        title = head[0x134:0x143].rstrip(b"\x00").decode("latin-1", "replace")
        self._prop(out, "gb", "title", title)
        cgb = head[0x143]
        if cgb == 0xC0:
            out["format"] = "Game Boy Color ROM (CGB-only)"
        elif cgb == 0x80:
            out["format"] = "Game Boy Color ROM (CGB-compatible)"
        if head[0x146] == 0x03:
            self._prop(out, "gb", "super_game_boy", "yes")
        ct = head[0x147]
        self._prop(out, "gb", "cartridge_type", self._GB_CART.get(ct, hex(ct)))
        rc = head[0x148]
        self._prop(out, "gb", "rom_size_kib", 32 << rc if rc <= 8 else None)
        self._prop(out, "gb", "ram_size_kib", self._GB_RAM.get(head[0x149], "?"))
        self._prop(
            out, "gb", "destination", "Japan" if head[0x14A] == 0 else "non-Japan"
        )
        # Header checksum covers 0x134..0x14C (documented algorithm).
        chk = 0
        for b in head[0x134:0x14D]:
            chk = (chk - b - 1) & 0xFF
        self._prop(
            out, "gb", "header_checksum_valid", "yes" if chk == head[0x14D] else "no"
        )
        self._prop(
            out,
            "gb",
            "nintendo_logo",
            "valid" if head[0x104:0x134] == self._GB_LOGO else "invalid",
        )

    def _p_rom_gba(self, p, head, out):
        out["family"] = "rom"
        out["format"] = "Game Boy Advance ROM"
        if len(head) >= 0xC0:
            title = head[0xA0:0xAC].rstrip(b"\x00").decode("latin-1", "replace")
            game = head[0xAC:0xB0].decode("latin-1", "replace")
            maker = head[0xB0:0xB2].decode("latin-1", "replace")
            self._prop(out, "gba", "title", title)
            self._prop(out, "gba", "game_code", game)
            self._prop(out, "gba", "maker_code", maker)
            self._prop(out, "gba", "main_unit_code", head[0xB3])
            self._prop(out, "gba", "software_version", head[0xBC])
            self._prop(
                out, "gba", "fixed_byte_valid", "yes" if head[0xB2] == 0x96 else "no"
            )
            # Header checksum over 0xA0..0xBC (documented complement algorithm).
            chk = 0
            for b in head[0xA0:0xBD]:
                chk = (chk - b) & 0xFF
            chk = (chk - 0x19) & 0xFF
            self._prop(
                out,
                "gba",
                "header_checksum_valid",
                "yes" if chk == head[0xBD] else "no",
            )

    def _p_rom_nds(self, p, head, out):
        out["family"] = "rom"
        out["format"] = "Nintendo DS ROM"
        if len(head) >= 0x20:
            title = head[0x00:0x0C].rstrip(b"\x00").decode("latin-1", "replace")
            code = head[0x0C:0x10].decode("latin-1", "replace")
            maker = head[0x10:0x12].decode("latin-1", "replace")
            unit = head[0x12]
            cap = head[0x14]
            self._prop(out, "nds", "title", title)
            self._prop(out, "nds", "game_code", code)
            self._prop(out, "nds", "maker_code", maker)
            self._prop(
                out,
                "nds",
                "unit_code",
                {0: "NDS", 2: "NDS+DSi", 3: "DSi"}.get(unit, hex(unit)),
            )
            self._prop(
                out, "nds", "capacity_bytes", (128 * 1024) << cap if cap < 24 else None
            )
            self._prop(out, "nds", "rom_version", head[0x1E])

    def _p_rom_3ds(self, p, head, out):
        out["family"] = "rom"
        ext = self._ext_of(p)
        out["format"] = {
            ".cia": "3DS CIA installable",
            ".xci": "3DS/Switch cartridge",
        }.get(ext, "Nintendo 3DS ROM")
        # NCSD magic 'NCSD' at 0x100.
        try:
            with open(p, "rb") as fh:
                fh.seek(0x100)
                if fh.read(4) == b"NCSD":
                    out["format"] = "Nintendo 3DS NCSD image"
                    self._prop(out, "3ds", "magic", "NCSD")
        except OSError:
            pass

    def _p_rom_genesis(self, p, head, out):
        out["family"] = "rom"
        out["format"] = "Sega Genesis/Mega Drive ROM"
        hb = self._read_at(p, head, 0x100, 0x100)
        if len(hb) < 0x100 or hb[:4] not in (b"SEGA", b"SEG "):
            return
        self._prop(
            out, "genesis", "system", hb[0x00:0x10].decode("latin-1", "replace").strip()
        )
        self._prop(
            out,
            "genesis",
            "copyright",
            hb[0x10:0x20].decode("latin-1", "replace").strip(),
        )
        dom = hb[0x20:0x50].rstrip(b"\x00 ").decode("latin-1", "replace").strip()
        ovr = hb[0x50:0x80].rstrip(b"\x00 ").decode("latin-1", "replace").strip()
        if dom:
            self._prop(out, "genesis", "domestic_title", dom)
        if ovr:
            self._prop(out, "genesis", "overseas_title", ovr)
        self._prop(
            out, "genesis", "serial", hb[0x80:0x8E].decode("latin-1", "replace").strip()
        )
        self._prop(
            out, "genesis", "checksum", hex(struct.unpack(">H", hb[0x8E:0x90])[0])
        )
        rom_start, rom_end = struct.unpack(">II", hb[0xA0:0xA8])
        self._prop(out, "genesis", "rom_end_address", hex(rom_end))
        self._prop(
            out,
            "genesis",
            "region",
            hb[0xF0:0xF3].rstrip(b"\x00 ").decode("latin-1", "replace"),
        )

    def _p_rom_generic(self, p, head, out):
        out["family"] = "rom"
        ext = self._ext_of(p)
        labels = {
            ".a26": "Atari 2600 ROM",
            ".a78": "Atari 7800 ROM",
            ".col": "ColecoVision ROM",
            ".int": "Intellivision ROM",
            ".lnx": "Atari Lynx ROM",
            ".pce": "PC Engine ROM",
            ".gg": "Game Gear ROM",
            ".sms": "Master System ROM",
            ".32x": "Sega 32X ROM",
            ".ngp": "Neo Geo Pocket ROM",
            ".pbp": "PSP EBOOT (PBP)",
            ".bios": "BIOS image",
            ".chd": "MAME CHD image",
            ".rvz": "Dolphin RVZ image",
            ".wbfs": "Wii WBFS image",
            ".gcm": "GameCube disc image",
            ".cso": "Compressed ISO",
        }
        out["format"] = labels.get(ext, "game ROM / disc image")
        if head[:8] == b"MComprHD":
            out["format"] = "MAME CHD (compressed hunks)"
            if len(head) >= 16:
                self._prop(
                    out, "chd", "header_length", struct.unpack(">I", head[8:12])[0]
                )
                self._prop(out, "chd", "version", struct.unpack(">I", head[12:16])[0])
        if ext == ".pbp" and head[:4] == b"\x00PBP":
            self._prop(out, "pbp", "magic", "PBP")

    # ==================================================================
    # Packet captures & Apple binary plist
    # ==================================================================
    def _p_pcap(self, p, head, out):
        out["family"] = "capture"
        out["format"] = "libpcap capture"
        endian = "<" if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        if len(head) >= 24:
            vmaj, vmin = struct.unpack(endian + "HH", head[4:8])
            linktype = struct.unpack(endian + "I", head[20:24])[0]
            self._prop(out, "pcap", "version", f"{vmaj}.{vmin}")
            self._prop(out, "pcap", "linktype", linktype)
            if head[:4] in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
                out["format"] = "libpcap capture (nanosecond)"

    def _p_pcapng(self, p, head, out):
        out["family"] = "capture"
        out["format"] = "pcapng capture"
        if len(head) >= 12:
            self._prop(
                out, "pcapng", "block_total_length", struct.unpack("<I", head[4:8])[0]
            )

    def _p_snoop(self, p, head, out):
        out["family"] = "capture"
        out["format"] = "Sun snoop capture"
        if len(head) >= 16:
            ver, dl = struct.unpack(">II", head[8:16])
            self._prop(out, "snoop", "version", ver)
            self._prop(out, "snoop", "datalink_type", dl)

    def _p_bplist(self, p, head, out):
        out["family"] = "container"
        ext = self._ext_of(p)
        out["format"] = {
            ".webarchive": "Safari Web Archive (bplist)",
            ".pkpass": "Apple Wallet pass",
        }.get(ext, "Apple binary property list")
        self._prop(out, "bplist", "version", head[6:8].decode("latin-1", "replace"))

    # ==================================================================
    # Trackers / Lua / WMF / EMF
    # ==================================================================
    def _p_tracker(self, p, head, out):
        data = head
        out["family"] = "audio"
        out["format"] = "tracker module"
        if data[:17] == b"Extended Module: ":
            out["format"] = "FastTracker II module (XM)"
            self._prop(out, "tracker", "kind", "XM")
        elif data[:4] == b"IMPM":
            out["format"] = "Impulse Tracker module (IT)"
        elif data[0x2C:0x30] == b"SCRM":
            out["format"] = "ScreamTracker 3 module (S3M)"
        elif data[:4] in (b"MMD0", b"MMD1", b"MMD2", b"MMD3"):
            out["format"] = "OctaMED module (MED)"
        else:
            self._prop(out, "tracker", "signature", data[:4].hex())

    def _p_lua(self, p, head, out):
        out["family"] = "bytecode"
        out["format"] = "Lua bytecode"
        if len(head) >= 6:
            self._prop(out, "lua", "version", f"{head[4] >> 4}.{head[4] & 0xf}")

    def _p_elc(self, p, head, out):
        out["family"] = "bytecode"
        out["format"] = "Emacs Lisp bytecode (.elc)"

    def _p_wmf(self, p, head, out):
        data = head
        out["family"] = "image"
        ext = self._ext_of(p)
        if data[:4] == b"\xd7\xcd\xc6\x9a":
            out["format"] = "Placeable Windows Metafile (WMF)"
        elif b" EMF" in data[:44] or data[40:44] == b" EMF":
            out["format"] = "Enhanced Metafile (EMF)"
            if len(data) >= 88:
                self._prop(out, "emf", "records", struct.unpack("<I", data[48:52])[0])
        elif ext in (".cgm",):
            out["format"] = "Computer Graphics Metafile (CGM)"
        else:
            out["format"] = "Windows Metafile"

    def _p_openexr(self, p, head, out):
        return self._p_exr(p, head, out)

    # ==================================================================
    # Forensic-only families (real profile; no fabricated structure)
    # ==================================================================
    def _p_forensic(self, p, head, out):
        fam = self.family_for(p.name) or "binary"
        out["family"] = self._FAMILY_GROUP.get(fam, "binary")
        out["format"] = self._FAMILY_LABEL.get(fam, "binary (forensic profile only)")
        out["notes"] = out["notes"] or "proprietary/undocumented; forensic profile only"

    # ==================================================================
    # Small helpers
    # ==================================================================
    @staticmethod
    def _ext_of(p: Path) -> str:
        name = p.name.lower()
        # Prefer a registered compound suffix (e.g. .tar.md5) else last component.
        parts = name.split(".")
        for i in range(1, len(parts)):
            suf = "." + ".".join(parts[i:])
            if suf in REGISTRY:
                return suf
        return p.suffix.lower()

    def _prop(self, out, group, name, value):
        # Single choke point for every free-text header field we surface. Strip
        # embedded NUL padding, then run the value through the guardrail scrubber
        # so any secret / credential / PII that happened to live in a header
        # string (e.g. a font's embedded license URL, a disk image's backing
        # path, a MATLAB description) is redacted and length-capped before it can
        # be indexed. Non-string values pass through untouched.
        if isinstance(value, str):
            if "\x00" in value:
                value = value.replace("\x00", "").strip()
            value = scrub(value, max_len=512)
        out["properties"].append((group, name, value))

    @staticmethod
    def _sec(name, sec_type, offset, size):
        return {
            "name": str(name)[:200],
            "sec_type": sec_type,
            "file_offset": offset,
            "size": size,
        }

    @staticmethod
    def _tail(p: Path, n: int) -> bytes:
        try:
            with open(p, "rb") as fh:
                sz = p.stat().st_size
                fh.seek(max(0, sz - n))
                return fh.read(n)
        except OSError:
            return b""

    @staticmethod
    def _read_at(p: Path, head: bytes, off: int, n: int) -> bytes:
        """Return ``n`` bytes at absolute offset ``off``, from the head window if
        it is already covered, else by a bounded seek+read (never fabricates)."""
        if off + n <= len(head):
            return head[off : off + n]
        try:
            with open(p, "rb") as fh:
                fh.seek(off)
                return fh.read(n)
        except OSError:
            return b""

    @staticmethod
    def _read_size(p: Path) -> bytes:
        return b""


# --- family metadata (labels + coarse group) for forensic dispositions --------
BinaryFormatParser._FAMILY_LABEL = {
    "forensic_audio": "audio project/preset (proprietary)",
    "codec_raw": "raw/opaque audio codec stream",
    "design_forensic": "design/graphics document (proprietary)",
    "model_3d_forensic": "3D/CAD model (proprietary)",
    "ml_forensic": "ML model/weights container",
    "instrument_forensic": "scientific instrument data",
    "geo_forensic": "geospatial dataset",
    "stat_forensic": "statistical software dataset",
    "doc_forensic": "document/e-book/office (proprietary)",
    "firmware_forensic": "firmware/EDA/embedded image",
    "trace_forensic": "trace/log/forensic capture",
    "font_forensic": "font source/metrics",
    "bundle_forensic": "macOS/app bundle",
    "misc_forensic": "project/config/binary artifact",
    "partial": "partial/temporary download",
    "svgz": "gzip-compressed SVG",
    "mjpeg": "Motion JPEG stream",
    "sevenzip": "7-Zip archive",
    "rar": "RAR archive",
    "cab": "Microsoft Cabinet",
}
BinaryFormatParser._FAMILY_GROUP = {
    "forensic_audio": "audio",
    "codec_raw": "audio",
    "midi": "audio",
    "tracker": "audio",
    "codec_video": "video",
    "design_forensic": "image",
    "model_3d_forensic": "model",
    "ml_forensic": "model",
    "instrument_forensic": "scientific",
    "geo_forensic": "geospatial",
    "stat_forensic": "scientific",
    "doc_forensic": "document",
    "firmware_forensic": "firmware",
    "trace_forensic": "capture",
    "font_forensic": "font",
    "bundle_forensic": "package",
    "misc_forensic": "binary",
    "partial": "binary",
    "svgz": "image",
    "mjpeg": "video",
    "zip_pkg": "container",
    "zip_bundle": "container",
}

# --- dispatch: family -> bound parser method ---------------------------------
BinaryFormatParser._HANDLERS = {
    "isobmff": BinaryFormatParser._p_isobmff,
    "riff": BinaryFormatParser._p_riff,
    "ebml": BinaryFormatParser._p_ebml,
    "ogg": BinaryFormatParser._p_ogg,
    "asf": BinaryFormatParser._p_asf,
    "mpegts": BinaryFormatParser._p_mpegts,
    "mpegps": BinaryFormatParser._p_mpegps,
    "elementary_video": BinaryFormatParser._p_elementary,
    "adts": BinaryFormatParser._p_adts,
    "amr": BinaryFormatParser._p_amr,
    "codec_video": BinaryFormatParser._p_codec,
    "midi": BinaryFormatParser._p_midi,
    "swf": BinaryFormatParser._p_swf,
    "tiff": BinaryFormatParser._p_tiff,
    "jpeg": BinaryFormatParser._p_jpeg,
    "mjpeg": BinaryFormatParser._p_jpeg,
    "png_img": BinaryFormatParser._p_png,
    "jp2": BinaryFormatParser._p_jp2,
    "jxr": BinaryFormatParser._p_jxr,
    "jbig": BinaryFormatParser._p_jbig,
    "exr": BinaryFormatParser._p_exr,
    "gpu_texture": BinaryFormatParser._p_gpu,
    "image_hdr": BinaryFormatParser._p_image_hdr,
    "bmp": BinaryFormatParser._p_bmp,
    "ico": BinaryFormatParser._p_ico,
    "icns": BinaryFormatParser._p_icns,
    "gif": BinaryFormatParser._p_gif,
    "psd": BinaryFormatParser._p_psd,
    "xcf": BinaryFormatParser._p_xcf,
    "fbx": BinaryFormatParser._p_fbx,
    "blend": BinaryFormatParser._p_blend,
    "usd": BinaryFormatParser._p_usd,
    "gltf": BinaryFormatParser._p_gltf,
    "openvdb": BinaryFormatParser._p_openvdb,
    "zip_pkg": BinaryFormatParser._p_zip,
    "zip_bundle": BinaryFormatParser._p_zip,
    "gzip": BinaryFormatParser._p_gzip,
    "svgz": BinaryFormatParser._p_gzip,
    "ar": BinaryFormatParser._p_ar,
    "rpm": BinaryFormatParser._p_rpm,
    "xar": BinaryFormatParser._p_xar,
    "sevenzip": BinaryFormatParser._p_generic_archive,
    "rar": BinaryFormatParser._p_generic_archive,
    "cab": BinaryFormatParser._p_generic_archive,
    "disk_vhd": BinaryFormatParser._p_disk_vhd,
    "disk_vmdk": BinaryFormatParser._p_disk_vmdk,
    "disk_vdi": BinaryFormatParser._p_disk_vdi,
    "disk_qcow": BinaryFormatParser._p_disk_qcow,
    "disk_iso": BinaryFormatParser._p_disk_iso,
    "disk_dmg": BinaryFormatParser._p_disk_dmg,
    "disk_wim": BinaryFormatParser._p_disk_wim,
    "disk_squashfs": BinaryFormatParser._p_disk_squashfs,
    "disk_generic": BinaryFormatParser._p_disk_generic,
    "fs_super": BinaryFormatParser._p_fs_super,
    "der": BinaryFormatParser._p_der,
    "keystore": BinaryFormatParser._p_keystore,
    "hdf5": BinaryFormatParser._p_hdf5,
    "hdf4": BinaryFormatParser._p_hdf4,
    "netcdf": BinaryFormatParser._p_netcdf,
    "grib": BinaryFormatParser._p_grib,
    "fits": BinaryFormatParser._p_fits,
    "matlab": BinaryFormatParser._p_matlab,
    "npy": BinaryFormatParser._p_npy,
    "gguf": BinaryFormatParser._p_gguf,
    "tflite": BinaryFormatParser._p_tflite,
    "ion": BinaryFormatParser._p_ion,
    "smile": BinaryFormatParser._p_smile,
    "marshal": BinaryFormatParser._p_marshal,
    "msgpack": BinaryFormatParser._p_magicless_serial,
    "cbor": BinaryFormatParser._p_magicless_serial,
    "ubjson": BinaryFormatParser._p_magicless_serial,
    "bson": BinaryFormatParser._p_magicless_serial,
    "flatbuffers": BinaryFormatParser._p_magicless_serial,
    "protobuf": BinaryFormatParser._p_magicless_serial,
    "recordio": BinaryFormatParser._p_magicless_serial,
    "sfnt": BinaryFormatParser._p_sfnt,
    "woff": BinaryFormatParser._p_woff,
    "woff2": BinaryFormatParser._p_woff2,
    "eot": BinaryFormatParser._p_eot,
    "type1": BinaryFormatParser._p_type1,
    "dvi": BinaryFormatParser._p_dvi,
    "djvu": BinaryFormatParser._p_djvu,
    "pdf": BinaryFormatParser._p_pdf,
    "pcl": BinaryFormatParser._p_pcl,
    "rom_nes": BinaryFormatParser._p_rom_nes,
    "rom_n64": BinaryFormatParser._p_rom_n64,
    "rom_snes": BinaryFormatParser._p_rom_snes,
    "rom_gb": BinaryFormatParser._p_rom_gb,
    "rom_gba": BinaryFormatParser._p_rom_gba,
    "rom_nds": BinaryFormatParser._p_rom_nds,
    "rom_3ds": BinaryFormatParser._p_rom_3ds,
    "rom_genesis": BinaryFormatParser._p_rom_genesis,
    "rom_generic": BinaryFormatParser._p_rom_generic,
    "pcap": BinaryFormatParser._p_pcap,
    "pcapng": BinaryFormatParser._p_pcapng,
    "snoop": BinaryFormatParser._p_snoop,
    "bplist": BinaryFormatParser._p_bplist,
    "tracker": BinaryFormatParser._p_tracker,
    "lua": BinaryFormatParser._p_lua,
    "elc": BinaryFormatParser._p_elc,
    "wmf": BinaryFormatParser._p_wmf,
    # forensic-only families
    "forensic_audio": BinaryFormatParser._p_forensic,
    "codec_raw": BinaryFormatParser._p_forensic,
    "design_forensic": BinaryFormatParser._p_forensic,
    "model_3d_forensic": BinaryFormatParser._p_forensic,
    "ml_forensic": BinaryFormatParser._p_forensic,
    "instrument_forensic": BinaryFormatParser._p_forensic,
    "geo_forensic": BinaryFormatParser._p_forensic,
    "stat_forensic": BinaryFormatParser._p_forensic,
    "doc_forensic": BinaryFormatParser._p_forensic,
    "firmware_forensic": BinaryFormatParser._p_forensic,
    "trace_forensic": BinaryFormatParser._p_forensic,
    "font_forensic": BinaryFormatParser._p_forensic,
    "bundle_forensic": BinaryFormatParser._p_forensic,
    "misc_forensic": BinaryFormatParser._p_forensic,
    "partial": BinaryFormatParser._p_forensic,
}
