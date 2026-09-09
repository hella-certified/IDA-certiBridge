#![allow(non_snake_case)]

use std::fs;
use std::path::{Path, PathBuf};
use colored::Colorize;

pub struct WorkspacePaths
{
	pub rootDir: PathBuf,
	pub srcDir: PathBuf,
	#[allow(dead_code)]
	pub buildDir: PathBuf,
	pub portablePath: PathBuf,
	pub pluginsTargetDir: PathBuf,
	#[allow(dead_code)]
	pub basePort: u16,
}

impl WorkspacePaths
{
	pub fn discover() -> Self
	{
		let mut rootDir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
		if !rootDir.join("src/py").exists()
		{
			if let Some(parent) = rootDir.parent()
			{
				if parent.join("src/py").exists()
				{
					rootDir = parent.to_path_buf();
				}
				else if let Some(grandparent) = parent.parent()
				{
					if grandparent.join("src/py").exists()
					{
						rootDir = grandparent.to_path_buf();
					}
				}
			}
		}
		let configPath = ensureConfigFile(&rootDir);
		let (portablePath, pluginsTargetDir, basePort) = readConfigToml(&configPath);

		let srcDir = rootDir.join("src");
		let buildDir = rootDir.join("build");

		Self
		{
			rootDir,
			srcDir,
			buildDir,
			portablePath,
			pluginsTargetDir,
			basePort,
		}
	}
}

pub fn ensureConfigFile(rootDir: &Path) -> PathBuf
{
	let path = rootDir.join("config.toml");
	if !path.exists()
	{
		let defaultContent = "[ida]\r\nportablePath = \"\"\r\npluginsPath = \"\"\r\n\r\n[bridge]\r\nbasePort = 13371\r\nmaxPort = 13390\r\nhost = \"127.0.0.1\"\r\n\r\n[diary]\r\noutputMarkdown = \"DIARY.md\"\r\noutputJson = \"diary.json\"\r\n";
		let _ = fs::write(&path, defaultContent);
	}
	path
}

pub fn readConfigToml(path: &Path) -> (PathBuf, PathBuf, u16)
{
	let mut portablePath = PathBuf::new();
	let mut pluginsPath = PathBuf::new();
	let mut basePort: u16 = 13371;

	if let Ok(content) = fs::read_to_string(path)
	{
		for line in content.lines()
		{
			let trim = line.trim();
			if trim.starts_with("portablePath")
			{
				if let Some(val) = trim.split('=').nth(1)
				{
					let clean = val.trim().trim_matches('"');
					if !clean.is_empty()
					{
						portablePath = PathBuf::from(clean);
					}
				}
			}
			else if trim.starts_with("pluginsPath")
			{
				if let Some(val) = trim.split('=').nth(1)
				{
					let clean = val.trim().trim_matches('"');
					if !clean.is_empty()
					{
						pluginsPath = PathBuf::from(clean);
					}
				}
			}
			else if trim.starts_with("basePort")
			{
				if let Some(val) = trim.split('=').nth(1)
				{
					if let Ok(p) = val.trim().parse::<u16>()
					{
						basePort = p;
					}
				}
			}
		}
	}

	if pluginsPath.as_os_str().is_empty() && !portablePath.as_os_str().is_empty()
	{
		pluginsPath = portablePath.join("plugins");
	}

	if pluginsPath.as_os_str().is_empty() || !pluginsPath.exists()
	{
		if let Ok(idaUsr) = std::env::var("IDAUSR")
		{
			let candidate = PathBuf::from(&idaUsr).join("plugins");
			if candidate.exists()
			{
				pluginsPath = candidate;
			}
			else if PathBuf::from(&idaUsr).exists()
			{
				pluginsPath = PathBuf::from(&idaUsr);
			}
		}
	}

	if pluginsPath.as_os_str().is_empty() || !pluginsPath.exists()
	{
		if let Ok(idaDir) = std::env::var("IDA_DIR").or_else(|_| std::env::var("IDAPRO"))
		{
			let candidate = PathBuf::from(&idaDir).join("plugins");
			if candidate.exists()
			{
				pluginsPath = candidate;
			}
		}
	}

	#[cfg(windows)]
	if pluginsPath.as_os_str().is_empty() || !pluginsPath.exists()
	{
		if let Ok(appData) = std::env::var("APPDATA")
		{
			let candidate = PathBuf::from(&appData).join("Hex-Rays").join("IDA Pro").join("plugins");
			if candidate.exists()
			{
				pluginsPath = candidate;
			}
		}
	}

	(portablePath, pluginsPath, basePort)
}

pub fn updateConfigPaths(rootDir: &Path, portable: &str, plugins: &str)
{
	let configPath = rootDir.join("config.toml");
	let mut content = fs::read_to_string(&configPath).unwrap_or_default();

	let cleanPortable = portable.replace('\\', "/");
	let cleanPlugins = plugins.replace('\\', "/");

	if content.contains("portablePath =")
	{
		let mut lines: Vec<String> = Vec::new();
		for line in content.lines()
		{
			if line.trim().starts_with("portablePath")
			{
				lines.push(format!("portablePath = \"{}\"", cleanPortable));
			}
			else if line.trim().starts_with("pluginsPath")
			{
				lines.push(format!("pluginsPath = \"{}\"", cleanPlugins));
			}
			else
			{
				lines.push(line.to_string());
			}
		}
		content = lines.join("\r\n");
	}
	else
	{
		content = format!(
			"[ida]\r\nportablePath = \"{}\"\r\npluginsPath = \"{}\"\r\n\r\n[bridge]\r\nbasePort = 13371\r\nmaxPort = 13390\r\nhost = \"127.0.0.1\"\r\n\r\n[diary]\r\noutputMarkdown = \"DIARY.md\"\r\noutputJson = \"diary.json\"\r\n",
			cleanPortable, cleanPlugins
		);
	}

	let _ = fs::write(&configPath, content);
	println!("{}", "config.toml updated with new paths".green());
}
