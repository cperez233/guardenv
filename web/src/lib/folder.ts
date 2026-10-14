/**
 * Read a dropped or picked folder in the browser: text files only, skipping
 * dependency and build directories, binaries and anything over 2 MB. Nothing
 * is uploaded; files are read with the File API and scanned in this tab.
 */

export interface FolderFile {
  readonly path: string;
  readonly content: string;
}

export interface FolderRead {
  readonly files: readonly FolderFile[];
  readonly skipped: number;
  readonly capped: boolean;
}

export const MAX_FOLDER_FILES = 2000;
/** Files read at once: enough to keep the disk busy, few enough to stay responsive. */
const READ_BATCH = 24;

export type Progress = (read: number) => void;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", ".nuxt", ".venv", "venv", "__pycache__",
  ".mypy_cache", ".pytest_cache", ".ruff_cache", "coverage", "vendor", ".terraform", ".idea", ".vscode",
]);
const SKIP_EXT = /\.(png|jpe?g|gif|webp|avif|ico|bmp|tiff?|svgz|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|exe|dll|so|dylib|o|a|wasm|woff2?|ttf|otf|eot|mp3|mp4|mov|avi|webm|ogg|wav|flac|psd|sketch|fig|sqlite|db|lock|min\.js|map)$/i;

export function isScannablePath(path: string): boolean {
  const parts = path.split("/");
  if (parts.slice(0, -1).some((part) => SKIP_DIRS.has(part))) return false;
  return !SKIP_EXT.test(parts[parts.length - 1] ?? "");
}

async function readText(file: File): Promise<string | null> {
  if (file.size > MAX_FILE_BYTES) return null;
  const text = await file.text();
  // A NUL byte in the first 8 KiB is the same binary test the CLI uses.
  return text.slice(0, 8192).includes("\u0000") ? null : text;
}

/** Read candidate files in parallel batches, reporting progress after each batch. */
async function readAll(
  candidates: readonly { path: string; load: () => Promise<File> }[],
  onProgress: Progress | undefined,
): Promise<{ files: FolderFile[]; unreadable: number }> {
  const files: FolderFile[] = [];
  let unreadable = 0;
  for (let start = 0; start < candidates.length; start += READ_BATCH) {
    const batch = candidates.slice(start, start + READ_BATCH);
    const texts = await Promise.all(
      batch.map(async (candidate) => {
        try {
          return await readText(await candidate.load());
        } catch {
          return null;
        }
      }),
    );
    texts.forEach((content, index) => {
      const candidate = batch[index];
      if (content === null || candidate === undefined) unreadable += 1;
      else files.push({ path: candidate.path, content });
    });
    onProgress?.(Math.min(start + READ_BATCH, candidates.length));
  }
  return { files, unreadable };
}

/** Files picked through `<input webkitdirectory>`. */
export async function readPickedFiles(list: FileList, onProgress?: Progress): Promise<FolderRead> {
  const candidates: { path: string; load: () => Promise<File> }[] = [];
  let skipped = 0;
  let capped = false;
  for (const file of Array.from(list)) {
    const path = file.webkitRelativePath || file.name;
    if (!isScannablePath(path)) {
      skipped += 1;
      continue;
    }
    if (candidates.length >= MAX_FOLDER_FILES) {
      capped = true;
      break;
    }
    candidates.push({ path, load: () => Promise.resolve(file) });
  }
  const { files, unreadable } = await readAll(candidates, onProgress);
  return { files, skipped: skipped + unreadable, capped };
}

function entryFile(entry: FileSystemFileEntry): Promise<File> {
  return new Promise((resolve, reject) => { entry.file(resolve, reject); });
}

function entryChildren(entry: FileSystemDirectoryEntry): Promise<FileSystemEntry[]> {
  const reader = entry.createReader();
  const all: FileSystemEntry[] = [];
  return new Promise((resolve, reject) => {
    const next = (): void => {
      reader.readEntries((batch) => {
        if (batch.length === 0) resolve(all);
        else {
          all.push(...batch);
          next();
        }
      }, reject);
    };
    next();
  });
}

/** A drop that contains a directory; returns null when it is a plain file drop. */
export async function readDroppedFolder(items: DataTransferItemList, onProgress?: Progress): Promise<FolderRead | null> {
  const roots = Array.from(items)
    .map((item) => item.webkitGetAsEntry())
    .filter((entry): entry is FileSystemEntry => entry !== null);
  if (!roots.some((entry) => entry.isDirectory)) return null;

  const candidates: { path: string; load: () => Promise<File> }[] = [];
  let skipped = 0;
  let capped = false;
  const walk = async (entry: FileSystemEntry, prefix: string): Promise<void> => {
    if (capped) return;
    const path = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isDirectory) {
      if (SKIP_DIRS.has(entry.name)) {
        skipped += 1;
        return;
      }
      for (const child of await entryChildren(entry as FileSystemDirectoryEntry)) await walk(child, path);
      return;
    }
    if (!isScannablePath(path)) {
      skipped += 1;
      return;
    }
    if (candidates.length >= MAX_FOLDER_FILES) {
      capped = true;
      return;
    }
    candidates.push({ path, load: () => entryFile(entry as FileSystemFileEntry) });
  };
  for (const root of roots) await walk(root, "");
  const { files, unreadable } = await readAll(candidates, onProgress);
  return { files, skipped: skipped + unreadable, capped };
}
