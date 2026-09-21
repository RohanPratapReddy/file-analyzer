"""Weight-free media-metric extraction for DataAnalyzer.

This module pulls **real, parameter-free** perceptual/DSP metrics out of image,
audio and video files by *reusing* the analyzer classes that already live in the
repository under ``sentinel/backend/src/modules/models/ai`` — nothing here is a
re-implementation:

* **audio**  -> ``encoder/audio/audio_encoder`` acquisition + ``dynamics``:
  ``audio_to_samples_tensor`` -> ``samples_to_spectral_tensors`` ->
  ``extract_dynamics_275``.  The 275-D per-sample feature block is aggregated to
  the 35 catalog group-means (energy/zcr/spectral*/mfcc/chroma/pitch/hnr/...).
* **image**  -> ``decoder/vision/pipeline/dynamics_features.DynamicsFeatureBank``:
  a parameter-free bank whose self-contained helpers (GLCM, LBP, Gabor, Harris/
  LoG/DoG keypoints, radial power spectrum, Gibbs/entropy energies, colour
  moments, symmetry, wavelet, DCT, structure-tensor posture) are evaluated on the
  whole frame (all-ones mask) and reduced to named scalars.
* **video**  -> the image metrics averaged over a handful of evenly-spaced frames,
  plus a temporal *motion* metric (mean absolute inter-frame luma difference).

None of the above needs learned weights.  Metrics that genuinely need a model
(object detection / recognition) are handled separately by :meth:`detect_objects`,
which downloads a *small* pretrained detector (``hustvl/yolos-tiny`` via
``transformers``) into a caller-supplied directory so it can be deleted after a
test run.  Everything degrades gracefully: if a dependency, the repo package, or
the network is missing, the relevant method returns ``{}`` and never raises.

Compute is bounded (image side clamped, audio clip truncated, a fixed number of
video frames) so this stays within the analyzer's "bounded sample" contract.
"""

from __future__ import annotations

import math
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# ---------------------------------------------------------------------------
# repo-root discovery (so ``import sentinel.backend...`` resolves)
# ---------------------------------------------------------------------------


def _find_repo_root(start: Optional[Path] = None) -> Optional[Path]:
    """Walk upward until a dir containing ``sentinel/backend`` is found."""
    env = os.environ.get("SENTINEL_REPO_ROOT")
    if env and (Path(env) / "sentinel" / "backend").is_dir():
        return Path(env)
    here = (start or Path(__file__)).resolve()
    for base in [here] + list(here.parents):
        if (base / "sentinel" / "backend").is_dir():
            return base
    return None


class MediaMetricExtractor:
    """Lazily-loaded façade over the repo's weight-free media analyzers.

    All public methods return a flat ``{name: float|str}`` dict suitable for
    ``DataAnalyzer._add_properties`` and never raise — failures surface as an
    empty dict (optionally carrying an ``_error`` note).
    """

    def __init__(
        self,
        repo_root: Optional[Union[str, Path]] = None,
        *,
        models_dir: Optional[Union[str, Path]] = None,
        audio_fs_khz: float = 8.0,
        audio_max_seconds: float = 6.0,
        image_max_side: int = 512,
        video_frames: int = 8,
        detector_model: str = "hustvl/yolos-tiny",
        detector_score: float = 0.5,
    ) -> None:
        self.repo_root = Path(repo_root) if repo_root else _find_repo_root()
        self.models_dir = Path(models_dir) if models_dir else None
        self.audio_fs_khz = float(audio_fs_khz)
        self.audio_max_seconds = float(audio_max_seconds)
        self.image_max_side = int(image_max_side)
        self.video_frames = int(video_frames)
        self.detector_model = detector_model
        self.detector_score = float(detector_score)

        self._loaded = False           # weight-free deps resolved?
        self._audio_fns: Optional[tuple] = None
        self._bank = None              # DynamicsFeatureBank instance (reused)
        self._luma_fn = None
        self._torch = None
        self._detector = None          # (processor, model) once downloaded
        self._detector_failed = False

    # ------------------------------------------------------------------
    # lazy loading of the weight-free repo analyzers
    # ------------------------------------------------------------------
    def _ensure_loaded(self) -> bool:
        if self._loaded:
            return self._bank is not None or self._audio_fns is not None
        self._loaded = True
        if self.repo_root is None:
            return False
        if str(self.repo_root) not in sys.path:
            sys.path.insert(0, str(self.repo_root))
        AI = "sentinel.backend.src.modules.models.ai"
        try:
            import torch  # noqa
            self._torch = torch
        except Exception:
            return False
        # audio pipeline
        try:
            from importlib import import_module
            samples = import_module(AI + ".encoder.audio.audio_encoder.acquisition.samples")
            spectral = import_module(AI + ".encoder.audio.audio_encoder.acquisition.spectral")
            extract = import_module(AI + ".encoder.audio.audio_encoder.dynamics.extract")
            catalog = import_module(AI + ".encoder.audio.audio_encoder.dynamics.catalog")
            self._audio_fns = (
                samples.audio_to_samples_tensor,
                spectral.samples_to_spectral_tensors,
                extract.extract_dynamics_275,
                catalog.GROUP_SLICES,
            )
        except Exception:
            self._audio_fns = None
        # vision bank
        try:
            from importlib import import_module
            vmod = import_module(AI + ".decoder.vision.pipeline.dynamics_features")
            self._bank = vmod.DynamicsFeatureBank().eval()
            self._luma_fn = getattr(vmod, "_luma", None)
        except Exception:
            self._bank = None
        return self._bank is not None or self._audio_fns is not None

    # ==================================================================
    # IMAGE
    # ==================================================================
    def _load_image_tensor(self, path: Union[str, Path]):
        """RGB float32 (1,3,H,W) in [0,1], long side clamped to ``image_max_side``."""
        torch = self._torch
        from PIL import Image
        import numpy as np
        with Image.open(path) as im:
            im = im.convert("RGB")
            w, h = im.size
            m = max(w, h)
            if m > self.image_max_side:
                s = self.image_max_side / float(m)
                im = im.resize((max(1, int(w * s)), max(1, int(h * s))))
            arr = np.asarray(im, dtype="float32") / 255.0    # (H,W,3)
        t = torch.from_numpy(arr).permute(2, 0, 1).unsqueeze(0).contiguous()
        return t

    def _luma_of(self, img):
        torch = self._torch
        if self._luma_fn is not None:
            try:
                return self._luma_fn(img)
            except Exception:
                pass
        # Rec.601 luma fallback -> (1,1,H,W)
        r, g, b = img[:, 0:1], img[:, 1:2], img[:, 2:3]
        return 0.299 * r + 0.587 * g + 0.114 * b

    def _image_metrics_from_tensor(self, img) -> Dict[str, float]:
        torch = self._torch
        bank = self._bank
        out: Dict[str, float] = {}
        with torch.no_grad():
            luma = self._luma_of(img)
            mask = torch.ones_like(luma)

            def f(v):
                return float(v)

            # --- GLCM texture (contrast, homogeneity, energy, entropy, corr) ---
            try:
                g = bank._glcm(luma)
                out.update(glcm_contrast=f(g[0]), glcm_homogeneity=f(g[1]),
                           glcm_energy=f(g[2]), glcm_entropy=f(g[3]),
                           glcm_correlation=f(g[4]))
            except Exception:
                pass
            # --- Gibbs / information energies ---
            try:
                e = bank._energy_info(luma, mask)
                out.update(gradient_energy=f(e[0]), sharpness=f(e[1]),
                           total_variation=f(e[2]), gibbs_energy=f(e[3]),
                           intensity_entropy=f(e[4]), negentropy=f(e[7]),
                           mean_luma=f(e[9]))
            except Exception:
                pass
            # --- radial power spectrum ---
            try:
                s = bank._spectrum(luma)          # 16 radial + ent + centroid
                radial = s[:16]
                hf = float(radial[8:].sum())
                out.update(spectral_entropy=f(s[16]), spectral_centroid=f(s[17]),
                           high_freq_ratio=hf)
            except Exception:
                pass
            # --- keypoint / edge density ---
            try:
                k = bank._keypoints(luma)
                out.update(corner_density=f(k[0]), corner_response=f(k[1]),
                           edge_density=f(k[5]))
            except Exception:
                pass
            # --- Gabor oriented-energy anisotropy ---
            try:
                gb = bank._gabor(luma).reshape(4, 4)   # 4 orient x [absmean,std,absmax,posfrac]
                absmean = gb[:, 0]
                out.update(gabor_energy=f(absmean.mean()),
                           gabor_anisotropy=f(absmean.std()))
            except Exception:
                pass
            # --- LBP micro-texture (entropy + uniformity of riu2 hist) ---
            try:
                lb = bank._lbp(luma)
                lb = lb / (lb.sum() + 1e-8)
                ent = float(-(lb * (lb + 1e-8).log()).sum())
                out.update(lbp_entropy=ent, lbp_uniformity=f((lb ** 2).sum()))
            except Exception:
                pass
            # --- colour moments / colorfulness ---
            try:
                c = bank._color_moments(img, mask)
                out.update(red_mean=f(c[0]), green_mean=f(c[3]), blue_mean=f(c[6]),
                           chroma=f(c[11]), colorfulness=f(c[12]),
                           brightness_range=f(c[15]))
            except Exception:
                pass
            # --- symmetry ---
            try:
                sy = bank._symmetry(luma, mask)
                out.update(symmetry_lr=f(sy[0]), symmetry_tb=f(sy[1]),
                           symmetry_rot180=f(sy[2]))
            except Exception:
                pass
            # --- structure-tensor posture (coherence, orientation entropy) ---
            try:
                po = bank._posture(luma)
                out.update(texture_coherence=f(po[1]), orientation_entropy=f(po[5]))
            except Exception:
                pass
            # --- wavelet sub-band energies (per level) ---
            try:
                wv = bank._wavelet(luma).reshape(3, 3)
                out.update(wavelet_energy_l1=f(wv[0].mean()),
                           wavelet_energy_l2=f(wv[1].mean()),
                           wavelet_energy_l3=f(wv[2].mean()))
            except Exception:
                pass
            # --- DCT DC / AC energy ---
            try:
                dc = bank._dct(luma)
                out.update(dct_dc=f(dc[0]), dct_ac_energy=f((dc[1:] ** 2).sum()))
            except Exception:
                pass
        # round for compact storage
        return {k: round(v, 6) for k, v in out.items()
                if isinstance(v, float) and math.isfinite(v)}

    def image_metrics(self, path: Union[str, Path]) -> Dict[str, float]:
        if not self._ensure_loaded() or self._bank is None:
            return {}
        try:
            img = self._load_image_tensor(path)
            return self._image_metrics_from_tensor(img)
        except Exception as err:  # never break the analyzer
            return {"_error": f"image_metrics: {type(err).__name__}: {err}"[:200]}

    # ==================================================================
    # AUDIO
    # ==================================================================
    @staticmethod
    def _ffprobe_sr(path: str) -> Optional[int]:
        import json
        import shutil
        import subprocess
        if not shutil.which("ffprobe"):
            return None
        try:
            r = subprocess.run(
                ["ffprobe", "-v", "error", "-select_streams", "a:0",
                 "-show_entries", "stream=sample_rate", "-of", "json", path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
            )
            if r.returncode != 0:
                return None
            streams = json.loads(r.stdout.decode() or "{}").get("streams", [])
            if streams and streams[0].get("sample_rate"):
                return int(streams[0]["sample_rate"])
        except Exception:
            return None
        return None

    def _load_waveform(self, path: Union[str, Path]):
        """Mono float32 1-D torch tensor + source sample-rate (Hz).

        Primary path is ffmpeg (decodes wav/mp3/flac/ogg/m4a/opus/... and is
        truncated to ``audio_max_seconds`` at the decoder for free); stdlib
        ``wave`` is the dependency-free fallback for PCM WAV. (torchaudio is
        deliberately not used — its native lib is unreliable on this host.)"""
        torch = self._torch
        import shutil
        import subprocess
        import numpy as np
        if shutil.which("ffmpeg"):
            sr = self._ffprobe_sr(str(path)) or 0
            try:
                cmd = ["ffmpeg", "-v", "error"]
                if self.audio_max_seconds > 0:
                    cmd += ["-t", str(self.audio_max_seconds)]
                # if ffprobe couldn't learn the rate, force a known one so the
                # returned sample-rate is always correct for the decoded stream
                if sr <= 0:
                    sr = 22050
                cmd += ["-i", str(path), "-ac", "1", "-ar", str(sr), "-f", "f32le", "-"]
                r = subprocess.run(cmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=120)
                if r.returncode == 0 and r.stdout:
                    a = np.frombuffer(r.stdout, dtype="<f4")
                    if a.size:
                        return torch.from_numpy(a.copy()), float(sr)
            except Exception:
                pass
        # stdlib wave fallback (PCM WAV only)
        try:
            import wave
            import numpy as np
            with wave.open(str(path), "rb") as w:
                sr = w.getframerate()
                nch = w.getnchannels()
                sw = w.getsampwidth()
                raw = w.readframes(w.getnframes())
            dt = {1: np.int8, 2: np.int16, 4: np.int32}.get(sw)
            if dt is None:
                return None, 0.0
            a = np.frombuffer(raw, dtype=dt).astype("float32")
            peak = float(np.iinfo(dt).max) if dt != np.int8 else 128.0
            a = a / peak
            if nch > 1:
                a = a.reshape(-1, nch).mean(axis=1)
            return torch.from_numpy(a.copy()), float(sr)
        except Exception:
            return None, 0.0

    def audio_metrics(self, path: Union[str, Path]) -> Dict[str, float]:
        if not self._ensure_loaded() or self._audio_fns is None:
            return {}
        torch = self._torch
        try:
            to_samples, to_spectral, extract275, group_slices = self._audio_fns
            wav, sr = self._load_waveform(path)
            if wav is None or wav.numel() == 0 or sr <= 0:
                return {}
            # truncate to a bounded clip
            keep = int(self.audio_max_seconds * sr)
            if keep > 0 and wav.numel() > keep:
                wav = wav[:keep]
            bundle = to_samples(
                wav, self.audio_fs_khz, phase_count=1,
                fs_src_khz=sr / 1000.0, mono=True,
            )
            X = bundle["X"]
            if not isinstance(X, torch.Tensor) or X.numel() == 0:
                return {}
            spectral = to_spectral(X, self.audio_fs_khz)
            feats = extract275(X, self.audio_fs_khz, spectral=spectral)   # (n,P,275)
            agg = feats.reshape(-1, feats.shape[-1]).mean(dim=0)          # (275,)
            out: Dict[str, float] = {}
            for name, sl in group_slices.items():
                v = float(agg[sl].mean())
                if math.isfinite(v):
                    out["dyn_" + name] = round(v, 6)
            out["duration_seconds"] = round(float(bundle.get("duration_s", 0.0)), 4)
            out["analysis_fs_hz"] = int(self.audio_fs_khz * 1000)
            out["source_fs_hz"] = int(sr)
            out["samples_analyzed"] = int(bundle.get("n", 0))
            return out
        except Exception as err:
            return {"_error": f"audio_metrics: {type(err).__name__}: {err}"[:200]}

    # ==================================================================
    # VIDEO
    # ==================================================================
    def video_metrics(self, path: Union[str, Path]) -> Dict[str, float]:
        if not self._ensure_loaded() or self._bank is None:
            return {}
        torch = self._torch
        try:
            import cv2
            import numpy as np
            cap = cv2.VideoCapture(str(path))
            if not cap.isOpened():
                cap.release()
                return {}
            total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 0
            k = max(1, self.video_frames)
            if total > 0:
                idxs = [int(i * (total - 1) / max(1, k - 1)) for i in range(k)] if k > 1 else [0]
            else:
                idxs = list(range(k))
            per_frame: List[Dict[str, float]] = []
            lumas: List[Any] = []
            for fi in idxs:
                if total > 0:
                    cap.set(cv2.CAP_PROP_POS_FRAMES, fi)
                ok, frame = cap.read()
                if not ok or frame is None:
                    continue
                rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                h, w = rgb.shape[:2]
                m = max(h, w)
                if m > self.image_max_side:
                    s = self.image_max_side / float(m)
                    rgb = cv2.resize(rgb, (max(1, int(w * s)), max(1, int(h * s))))
                arr = rgb.astype("float32") / 255.0
                img = torch.from_numpy(arr).permute(2, 0, 1).unsqueeze(0).contiguous()
                per_frame.append(self._image_metrics_from_tensor(img))
                lumas.append(self._luma_of(img))
            cap.release()
            if not per_frame:
                return {}
            # average each metric across sampled frames
            keys = set().union(*[d.keys() for d in per_frame])
            out: Dict[str, float] = {}
            for key in keys:
                vals = [d[key] for d in per_frame if key in d]
                if vals:
                    out["vid_" + key] = round(sum(vals) / len(vals), 6)
            # temporal motion: mean abs inter-frame luma difference
            if len(lumas) > 1:
                diffs = [float((lumas[i] - lumas[i - 1]).abs().mean())
                         for i in range(1, len(lumas))]
                out["motion_mean"] = round(sum(diffs) / len(diffs), 6)
            out["frames_sampled"] = len(per_frame)
            return out
        except Exception as err:
            return {"_error": f"video_metrics: {type(err).__name__}: {err}"[:200]}

    # ==================================================================
    # MODEL-BASED (needs weights): small pretrained detector, downloaded
    # ==================================================================
    def _ensure_detector(self):
        if self._detector is not None or self._detector_failed:
            return self._detector
        try:
            # transformers eagerly imports torchaudio; on this host its native
            # lib fails to load (OSError, not ImportError) and would abort the
            # import. Neutralize it first *only if it is actually broken* so the
            # availability check degrades cleanly to "unavailable".
            if "torchaudio" not in sys.modules:
                try:
                    import torchaudio  # noqa: F401
                except Exception:
                    sys.modules["torchaudio"] = None  # type: ignore[assignment]
            from transformers import AutoImageProcessor, AutoModelForObjectDetection
            kw = {}
            if self.models_dir is not None:
                self.models_dir.mkdir(parents=True, exist_ok=True)
                kw["cache_dir"] = str(self.models_dir)
            proc = AutoImageProcessor.from_pretrained(self.detector_model, **kw)
            model = AutoModelForObjectDetection.from_pretrained(self.detector_model, **kw).eval()
            self._detector = (proc, model)
        except Exception:
            self._detector_failed = True
            self._detector = None
        return self._detector

    def detect_objects(self, path: Union[str, Path]) -> Dict[str, Any]:
        if not self._ensure_loaded():
            return {}
        det = self._ensure_detector()
        if det is None:
            return {}
        torch = self._torch
        try:
            import json
            from PIL import Image
            proc, model = det
            with Image.open(path) as im:
                im = im.convert("RGB")
                size = im.size[::-1]   # (h, w)
                inputs = proc(images=im, return_tensors="pt")
            with torch.no_grad():
                outputs = model(**inputs)
            target_sizes = torch.tensor([size])
            results = proc.post_process_object_detection(
                outputs, threshold=self.detector_score, target_sizes=target_sizes
            )[0]
            labels = results["labels"].tolist()
            scores = results["scores"].tolist()
            id2label = getattr(model.config, "id2label", {})
            named = [(id2label.get(int(l), str(l)), round(float(s), 4))
                     for l, s in zip(labels, scores)]
            named.sort(key=lambda t: t[1], reverse=True)
            distinct = sorted({n for n, _ in named})
            return {
                "object_count": len(named),
                "distinct_classes": len(distinct),
                "top_objects": json.dumps(named[:8]),
                "class_labels": json.dumps(distinct[:16]),
                "mean_confidence": round(sum(s for _, s in named) / len(named), 4)
                if named else 0.0,
                "detector_model": self.detector_model,
            }
        except Exception as err:
            return {"_error": f"detect_objects: {type(err).__name__}: {err}"[:200]}
