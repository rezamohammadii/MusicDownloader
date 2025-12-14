import os
import re
import sys
import requests

from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, unquote

from mutagen import File as MutagenFile

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLabel, QLineEdit,
    QProgressBar, QTextEdit, QMessageBox, QTableWidget, QTableWidgetItem,
    QAbstractItemView, QHeaderView, QCheckBox, QSplitter
)

AUDIO_EXT = ".mp3"


# ---------------------- utils ----------------------
def safe_name(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r'[\\/:*?"<>|]+', "_", s)
    s = re.sub(r"\s+", " ", s)
    return s[:140].strip()


def sanitize_filename(name: str) -> str:
    name = unquote(name).strip()
    name = re.sub(r'[\\/:*?"<>|]+', "_", name)
    return name or "file.mp3"


def filename_from_url(url: str) -> str:
    p = urlparse(url)
    base = os.path.basename(p.path) or "file.mp3"
    if not base.lower().endswith(AUDIO_EXT):
        base += AUDIO_EXT
    return sanitize_filename(base)


def is_http_url(s: str) -> bool:
    s = (s or "").lower()
    return s.startswith("http://") or s.startswith("https://")


def dedupe_keep_order(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out


# ---------------------- tag rename ----------------------
def read_mp3_artist_title(path: str):
    try:
        audio = MutagenFile(path, easy=True)
        if not audio:
            return None, None

        artist = None
        title = None

        if "artist" in audio and audio["artist"]:
            artist = audio["artist"][0]
        if "title" in audio and audio["title"]:
            title = audio["title"][0]

        if not artist and "albumartist" in audio and audio["albumartist"]:
            artist = audio["albumartist"][0]

        artist = safe_name(artist) if artist else None
        title = safe_name(title) if title else None
        return artist, title
    except Exception:
        return None, None


def rename_by_tags(path: str) -> str:
    artist, title = read_mp3_artist_title(path)
    if not artist and not title:
        return path

    folder = os.path.dirname(path)
    ext = os.path.splitext(path)[1].lower() or ".mp3"

    if artist and title:
        base = f"{artist} - {title}"
    elif title:
        base = f"{title}"
    else:
        base = f"{artist}"

    base = safe_name(base) or "track"
    new_path = os.path.join(folder, f"{base}{ext}")

    if os.path.abspath(new_path) == os.path.abspath(path):
        return path

    i = 1
    final_path = new_path
    while os.path.exists(final_path):
        final_path = os.path.join(folder, f"{base} ({i}){ext}")
        i += 1

    try:
        os.rename(path, final_path)
        return final_path
    except Exception:
        return path


# ---------------------- scanning (pasted HTML, chunked) ----------------------
def extract_mp3_links_from_big_text(raw_text: str, progress_cb=None, chunk_size=1024 * 1024):
    """
    Chunk-by-chunk scan on a big pasted text (minified/one-line friendly).
    Avoids heavy regex work when no ".mp3" substring is present.
    """
    mp3_regex = re.compile(
        r'(?i)(?:https?://|//|/)?[^\s"\'<>]{1,800}(?:\.mp3|\\\.mp3)(?:\?[^\s"\'<>]*)?'
    )

    total_len = len(raw_text)
    if total_len == 0:
        if progress_cb:
            progress_cb(100)
        return []

    processed = 0
    tail = ""
    tail_keep = 20000

    results = []
    seen = set()

    pos = 0
    while pos < total_len:
        chunk = raw_text[pos:pos + chunk_size]
        pos += chunk_size

        processed += len(chunk)
        window = tail + chunk

        lower = window.lower()
        if ".mp3" in lower or "\\.mp3" in lower:
            for m in mp3_regex.finditer(window):
                link = m.group(0).strip()
                if link not in seen:
                    seen.add(link)
                    results.append(link)

        tail = window[-tail_keep:] if len(window) > tail_keep else window

        if progress_cb:
            progress_cb(int(min(processed, total_len) / total_len * 100))

    if progress_cb:
        progress_cb(100)

    return results


# ---------------------- scanning (URLs list, streamed pages) ----------------------
def parse_urls_from_text(raw: str) -> list[str]:
    urls = []
    for line in raw.splitlines():
        u = line.strip()
        if not u or u.startswith("#"):
            continue
        urls.append(u)
    return dedupe_keep_order(urls)


def extract_mp3_links_from_streamed_html(response: requests.Response, base_url: str):
    mp3_regex = re.compile(
        r'(?i)(?:https?://|//|/)?[^\s"\'<>]{1,800}(?:\.mp3|\\\.mp3)(?:\?[^\s"\'<>]*)?'
    )

    results = []
    seen = set()

    tail = ""
    tail_keep = 20000

    for chunk in response.iter_content(chunk_size=1024 * 256, decode_unicode=True):
        if not chunk:
            continue
        window = tail + chunk

        lower = window.lower()
        if ".mp3" in lower or "\\.mp3" in lower:
            for m in mp3_regex.finditer(window):
                link = m.group(0).strip()
                link = urljoin(base_url, link)
                if link not in seen:
                    seen.add(link)
                    results.append(link)

        tail = window[-tail_keep:] if len(window) > tail_keep else window

    return results


# ---------------------- download ----------------------
def download_mp3(url: str, session: requests.Session, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)

    name = filename_from_url(url)
    path = os.path.join(output_dir, name)

    base, ext = os.path.splitext(name)
    i = 1
    while os.path.exists(path):
        path = os.path.join(output_dir, f"{base}_{i}{ext}")
        i += 1

    with session.get(url, stream=True, timeout=60) as r:
        r.raise_for_status()
        with open(path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 256):
                if chunk:
                    f.write(chunk)
    return path


# ---------------------- data model ----------------------
@dataclass
class FoundItem:
    source: str
    url: str
    downloadable: bool


# ---------------------- workers ----------------------
class ScanWorker(QThread):
    log = Signal(str)
    progress = Signal(int)       # 0..100
    found_items = Signal(list)   # list[FoundItem]
    finished_ok = Signal()
    failed = Signal(str)

    def __init__(self, raw_input: str, input_is_urls: bool, base_url_for_html: str):
        super().__init__()
        self.raw_input = raw_input
        self.input_is_urls = input_is_urls
        self.base_url_for_html = base_url_for_html.strip() or None
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            items: list[FoundItem] = []
            session = requests.Session()
            session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; MP3DownloaderGUI/2.0)"})

            if self.input_is_urls:
                page_urls = parse_urls_from_text(self.raw_input)
                if not page_urls:
                    self.found_items.emit([])
                    self.progress.emit(100)
                    self.finished_ok.emit()
                    return

                total_pages = len(page_urls)
                self.log.emit(f"Scanning {total_pages} page(s) ...")

                for i, page_url in enumerate(page_urls, 1):
                    if self._stop:
                        self.log.emit("Scan stopped by user.")
                        return
                    try:
                        with session.get(page_url, stream=True, timeout=60) as r:
                            r.raise_for_status()
                            found = extract_mp3_links_from_streamed_html(r, base_url=page_url)
                            found = dedupe_keep_order(found)
                            for link in found:
                                items.append(FoundItem(source=page_url, url=link, downloadable=is_http_url(link)))
                    except Exception as e:
                        self.log.emit(f"Failed page: {page_url} | {e}")

                    self.progress.emit(int(i / max(1, total_pages) * 100))

            else:
                self.log.emit("Scanning pasted HTML source (chunked) ...")

                def local_progress(p):
                    self.progress.emit(p)

                found = extract_mp3_links_from_big_text(self.raw_input, progress_cb=local_progress)
                found = dedupe_keep_order(found)

                resolved = []
                for link in found:
                    resolved.append(urljoin(self.base_url_for_html, link) if self.base_url_for_html else link)

                for link in resolved:
                    items.append(FoundItem(source="PASTED_HTML", url=link, downloadable=is_http_url(link)))

            # De-dup by URL globally
            seen = set()
            deduped = []
            for it in items:
                if it.url not in seen:
                    seen.add(it.url)
                    deduped.append(it)

            self.progress.emit(100)
            self.found_items.emit(deduped)
            self.finished_ok.emit()

        except Exception as e:
            self.failed.emit(str(e))


class DownloadWorker(QThread):
    log = Signal(str)
    progress = Signal(int)          # 0..100 (by file count)
    finished_ok = Signal(int, int)  # ok, fail
    failed = Signal(str)

    def __init__(self, urls: list[str], output_dir: str, rename_enabled: bool):
        super().__init__()
        self.urls = urls
        self.output_dir = output_dir
        self.rename_enabled = rename_enabled
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            session = requests.Session()
            session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; MP3DownloaderGUI/2.0)"})

            total = len(self.urls)
            ok = 0
            fail = 0

            for i, url in enumerate(self.urls, 1):
                if self._stop:
                    self.log.emit("Download stopped by user.")
                    break

                try:
                    saved = download_mp3(url, session, self.output_dir)
                    ok += 1

                    if self.rename_enabled:
                        try:
                            renamed = rename_by_tags(saved)
                            if renamed != saved:
                                self.log.emit(f"Renamed: {os.path.basename(saved)} -> {os.path.basename(renamed)}")
                            else:
                                self.log.emit(f"Downloaded: {os.path.basename(saved)}")
                        except Exception as e:
                            self.log.emit(f"Downloaded: {os.path.basename(saved)} (rename failed: {e})")
                    else:
                        self.log.emit(f"Downloaded: {os.path.basename(saved)}")

                except Exception as e:
                    fail += 1
                    self.log.emit(f"Failed: {url} | {e}")

                self.progress.emit(int(i / max(1, total) * 100))

            self.progress.emit(100)
            self.finished_ok.emit(ok, fail)

        except Exception as e:
            self.failed.emit(str(e))


# ---------------------- UI ----------------------
DARK_QSS = """
QWidget { font-size: 11pt; }
QMainWindow { background: #111318; color: #e9e9ea; }
QLabel { color: #e9e9ea; }
QLineEdit, QTextEdit, QTableWidget {
  background: #161a22; color: #e9e9ea; border: 1px solid #2a2f3a; border-radius: 10px;
}
QPushButton {
  background: #2a2f3a; color: #e9e9ea; border: 1px solid #3a4150; padding: 8px 12px;
  border-radius: 12px;
}
QPushButton:hover { background: #343b49; }
QPushButton:disabled { color: #8a8f9a; background: #222734; border-color: #2a2f3a; }
QProgressBar {
  border: 1px solid #2a2f3a; border-radius: 12px; text-align: center; background: #161a22;
}
QProgressBar::chunk { background: #3a7bd5; border-radius: 12px; }
QHeaderView::section { background: #1b2030; color: #e9e9ea; border: 0; padding: 6px; }
QCheckBox { color: #e9e9ea; }
"""


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MP3 Extractor & Downloader")
        self.resize(1200, 720)

        self.found: list[FoundItem] = []

        root = QWidget()
        self.setCentralWidget(root)
        main = QVBoxLayout(root)

        splitter = QSplitter(Qt.Horizontal)
        main.addWidget(splitter, 1)

        # -------- Left: Input + Settings --------
        left = QWidget()
        left_l = QVBoxLayout(left)

        left_l.addWidget(QLabel("Input (paste here)"))
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText(
            "Paste here...\n\n"
            "If the checkbox is ON: paste one PAGE URL per line.\n"
            "If the checkbox is OFF: paste the full HTML source code."
        )
        left_l.addWidget(self.input_text, 3)

        self.chk_input_is_urls = QCheckBox("Input is a list of page URLs (one per line)")
        self.chk_input_is_urls.setChecked(True)
        left_l.addWidget(self.chk_input_is_urls)

        left_l.addWidget(QLabel("Base URL (optional, helps resolve relative .mp3 links for pasted HTML)"))
        self.base_edit = QLineEdit()
        self.base_edit.setPlaceholderText("Example: https://example.com/")
        left_l.addWidget(self.base_edit)

        left_l.addWidget(QLabel("Output folder"))
        out_row = QHBoxLayout()
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Choose output folder...")
        self.btn_output = QPushButton("Browse")
        out_row.addWidget(self.output_edit, 1)
        out_row.addWidget(self.btn_output)
        left_l.addLayout(out_row)

        self.chk_rename = QCheckBox("Rename files using ID3 tags (Artist - Title)")
        self.chk_rename.setChecked(True)
        left_l.addWidget(self.chk_rename)

        self.chk_only_downloadable = QCheckBox("Show only downloadable (http/https)")
        self.chk_only_downloadable.setChecked(False)
        left_l.addWidget(self.chk_only_downloadable)

        ctrl = QHBoxLayout()
        self.btn_scan = QPushButton("Scan")
        self.btn_download_all = QPushButton("Download All")
        self.btn_download_selected = QPushButton("Download Selected")
        self.btn_stop = QPushButton("Stop")

        self.btn_download_all.setEnabled(False)
        self.btn_download_selected.setEnabled(False)
        self.btn_stop.setEnabled(False)

        ctrl.addWidget(self.btn_scan)
        ctrl.addWidget(self.btn_download_all)
        ctrl.addWidget(self.btn_download_selected)
        ctrl.addWidget(self.btn_stop)
        left_l.addLayout(ctrl)

        splitter.addWidget(left)

        # -------- Right: Results + Log --------
        right = QWidget()
        right_l = QVBoxLayout(right)

        right_l.addWidget(QLabel("Found MP3 links"))
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Select", "MP3 URL", "Source"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        right_l.addWidget(self.table, 3)

        right_l.addWidget(QLabel("Progress"))
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        right_l.addWidget(self.progress)

        right_l.addWidget(QLabel("Log"))
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        right_l.addWidget(self.log, 2)

        splitter.addWidget(right)
        splitter.setSizes([430, 770])

        # Workers
        self.scan_worker: ScanWorker | None = None
        self.dl_worker: DownloadWorker | None = None

        # Signals
        self.btn_output.clicked.connect(self.pick_output)
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_download_all.clicked.connect(self.download_all)
        self.btn_download_selected.clicked.connect(self.download_selected)
        self.btn_stop.clicked.connect(self.stop_active)
        self.chk_only_downloadable.stateChanged.connect(self.refresh_table)

    def append_log(self, msg: str):
        self.log.append(msg)

    def pick_output(self):
        d = QFileDialog.getExistingDirectory(self, "Select output folder")
        if d:
            self.output_edit.setText(d)

    def has_downloadables(self) -> bool:
        return any(it.downloadable for it in self.found)

    def set_busy(self, busy: bool):
        self.btn_scan.setEnabled(not busy)
        self.btn_output.setEnabled(not busy)
        self.btn_download_all.setEnabled((not busy) and self.has_downloadables())
        self.btn_download_selected.setEnabled((not busy) and self.has_downloadables())
        self.btn_stop.setEnabled(busy)

    def refresh_table(self):
        self.table.setRowCount(0)
        only_dl = self.chk_only_downloadable.isChecked()

        visible = [it for it in self.found if (it.downloadable or not only_dl)]
        self.table.setRowCount(len(visible))

        for row, it in enumerate(visible):
            chk_item = QTableWidgetItem()
            chk_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            chk_item.setCheckState(Qt.Unchecked)

            if not it.downloadable:
                chk_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)

            url_item = QTableWidgetItem(it.url)
            src_item = QTableWidgetItem(it.source)

            if not it.downloadable:
                url_item.setForeground(Qt.gray)
                src_item.setForeground(Qt.gray)

            self.table.setItem(row, 0, chk_item)
            self.table.setItem(row, 1, url_item)
            self.table.setItem(row, 2, src_item)

        self.btn_download_all.setEnabled(self.has_downloadables())
        self.btn_download_selected.setEnabled(self.has_downloadables())

    def start_scan(self):
        raw = self.input_text.toPlainText().strip()
        if not raw:
            QMessageBox.warning(self, "Missing input", "Please paste input text (URLs or HTML source).")
            return

        outdir = self.output_edit.text().strip()
        if not outdir:
            QMessageBox.warning(self, "Missing output folder", "Please choose an output folder.")
            return

        self.append_log("-----")
        self.append_log("Scan started...")
        self.progress.setValue(0)
        self.set_busy(True)

        self.found.clear()
        self.refresh_table()

        self.scan_worker = ScanWorker(
            raw_input=raw,
            input_is_urls=self.chk_input_is_urls.isChecked(),
            base_url_for_html=self.base_edit.text().strip(),
        )
        self.scan_worker.log.connect(self.append_log)
        self.scan_worker.progress.connect(self.progress.setValue)
        self.scan_worker.found_items.connect(self.on_scan_results)
        self.scan_worker.finished_ok.connect(self.on_scan_finished)
        self.scan_worker.failed.connect(self.on_worker_failed)
        self.scan_worker.start()

    def on_scan_results(self, items):
        self.found = items
        self.refresh_table()
        total = len(self.found)
        dl = sum(1 for x in self.found if x.downloadable)
        self.append_log(f"Found {total} unique mp3 link(s). Downloadable: {dl}")

    def on_scan_finished(self):
        self.append_log("Scan finished.")
        self.progress.setValue(100)
        self.set_busy(False)

    def on_worker_failed(self, err: str):
        self.append_log(f"ERROR: {err}")
        self.set_busy(False)
        QMessageBox.critical(self, "Error", err)

    def selected_download_urls(self) -> list[str]:
        urls = []
        only_dl = self.chk_only_downloadable.isChecked()
        visible = [it for it in self.found if (it.downloadable or not only_dl)]

        for row, it in enumerate(visible):
            chk = self.table.item(row, 0)
            if chk and chk.checkState() == Qt.Checked and it.downloadable:
                urls.append(it.url)

        return dedupe_keep_order(urls)

    def download_all(self):
        urls = dedupe_keep_order([it.url for it in self.found if it.downloadable])
        self.confirm_and_start_download(urls)

    def download_selected(self):
        urls = self.selected_download_urls()
        if not urls:
            QMessageBox.information(self, "Nothing selected", "Please check some downloadable links in the table.")
            return
        self.confirm_and_start_download(urls)

    def confirm_and_start_download(self, urls: list[str]):
        if not urls:
            QMessageBox.information(self, "No downloads", "No downloadable mp3 links were found/selected.")
            return

        outdir = self.output_edit.text().strip()
        if not outdir:
            QMessageBox.warning(self, "Missing output folder", "Please choose an output folder.")
            return

        msg = f"This will download {len(urls)} file(s) into:\n{outdir}\n\nContinue?"
        ok = QMessageBox.question(self, "Confirm download", msg, QMessageBox.Yes | QMessageBox.No)
        if ok != QMessageBox.Yes:
            return

        self.append_log("-----")
        self.append_log(f"Download started: {len(urls)} file(s)")
        self.progress.setValue(0)
        self.set_busy(True)

        self.dl_worker = DownloadWorker(
            urls=urls,
            output_dir=outdir,
            rename_enabled=self.chk_rename.isChecked()
        )
        self.dl_worker.log.connect(self.append_log)
        self.dl_worker.progress.connect(self.progress.setValue)
        self.dl_worker.finished_ok.connect(self.on_download_finished)
        self.dl_worker.failed.connect(self.on_worker_failed)
        self.dl_worker.start()

    def on_download_finished(self, ok: int, fail: int):
        self.append_log(f"Download finished. OK: {ok} | Failed: {fail}")
        self.progress.setValue(100)
        self.set_busy(False)
        QMessageBox.information(self, "Done", f"Downloads complete.\nOK: {ok}\nFailed: {fail}")

    def stop_active(self):
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.append_log("Stop requested (scan).")
        if self.dl_worker and self.dl_worker.isRunning():
            self.dl_worker.stop()
            self.append_log("Stop requested (download).")


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(DARK_QSS)

    w = MainWindow()
    w.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
