#![allow(non_snake_case)]

use std::fs;
use std::path::Path;

pub fn copyDirRecursive(src: &Path, dst: &Path)
{
	let _ = fs::create_dir_all(dst);
	if let Ok(entries) = fs::read_dir(src)
	{
		for entry in entries.flatten()
		{
			let path = entry.path();
			let destPath = dst.join(entry.file_name());
			if path.is_dir()
			{
				copyDirRecursive(&path, &destPath);
			}
			else
			{
				let _ = fs::copy(&path, &destPath);
			}
		}
	}
}
