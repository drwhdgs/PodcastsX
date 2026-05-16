import os
import hashlib

def get_md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def get_sha256(fname):
    hash_sha256 = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def extract_control(deb_path):
    with open("control", "r") as f:
        return f.read().strip()

packages_content = ""
# debs folder
debs_dir = "debs"
if not os.path.exists(debs_dir):
    os.makedirs(debs_dir)

for filename in os.listdir(debs_dir):
    if filename.endswith(".deb"):
        path = os.path.join(debs_dir, filename)
        size = os.path.getsize(path)
        md5 = get_md5(path)
        sha256 = get_sha256(path)
        
        control = extract_control(path)
        packages_content += control + "\n"
        packages_content += f"Filename: {path}\n"
        packages_content += f"Size: {size}\n"
        packages_content += f"MD5sum: {md5}\n"
        packages_content += f"SHA256: {sha256}\n"
        packages_content += "\n"

with open("Packages", "w") as f:
    f.write(packages_content)

print("Generated Packages file")
