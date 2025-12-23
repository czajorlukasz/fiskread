import os
import json
import hashlib
import time


def save_file_from_fsp(fsp, remote_path: str, local_root: str, nr_lokalu: str, prefix: str):
    """Download full file via FSP and save under local_root/<nr_lokalu>/<prefix>/<remote_path>.
    Returns dict with saved_path and sha256 or None on error.
    """
    try:
        # normalize remote path and split
        p = remote_path.strip('/')
        parts = p.split('/') if p else []
        # target path
        target_path = os.path.join(local_root, str(nr_lokalu), prefix, *parts)
        target_dir = os.path.dirname(target_path)
        os.makedirs(target_dir, exist_ok=True)
        # fetch full file
        data = fsp.read_file_fsp(remote_path)
        if not data:
            return None
        # write atomically
        tmp_path = target_path + '.tmp'
        with open(tmp_path, 'wb') as fh:
            fh.write(data)
        os.replace(tmp_path, target_path)
        # compute sha256
        sha = hashlib.sha256(data).hexdigest()
        meta = {
            'original_path': remote_path,
            'saved_path': target_path,
            'size': len(data),
            'sha256': sha,
            'saved_at': time.strftime('%Y-%m-%dT%H:%M:%S')
        }
        # write sidecar metadata
        meta_path = target_path + '.meta.json'
        with open(meta_path, 'w', encoding='utf-8') as mfh:
            json.dump(meta, mfh, ensure_ascii=False, indent=2)
        return meta
    except Exception:
        return None
