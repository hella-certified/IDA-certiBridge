#![allow(non_snake_case)]

use colored::Colorize;
use std::fs;
use crate::config::{updateConfigPaths, WorkspacePaths};
use crate::utils::fs::copyDirRecursive;
use crate::utils::process::logWithTime;

pub fn run(paths: &mut WorkspacePaths, args: &[String])
{
	if !args.is_empty()
	{
		let clean = args[0].trim();
		let portableBuf = std::path::PathBuf::from(clean);
		let pluginsBuf = if portableBuf.join("plugins").exists() || portableBuf.file_name().map_or(false, |n| n != "plugins")
		{
			portableBuf.join("plugins")
		}
		else
		{
			portableBuf.clone()
		};
		updateConfigPaths(&paths.rootDir, clean, &pluginsBuf.to_string_lossy());
		paths.portablePath = portableBuf;
		paths.pluginsTargetDir = pluginsBuf;
	}

	if paths.pluginsTargetDir.as_os_str().is_empty() || !paths.pluginsTargetDir.exists()
	{
		logWithTime(&"IDA plugins path not configured in config.toml".yellow().to_string());
		let input: String = dialoguer::Input::new()
			.with_prompt("Enter your IDA directory or plugins directory")
			.interact_text()
			.unwrap_or_default();

		if input.trim().is_empty()
		{
			logWithTime(&"no path provided; deployment aborted".red().to_string());
			return;
		}

		let clean = input.trim();
		let portableBuf = std::path::PathBuf::from(clean);
		let pluginsBuf = if portableBuf.join("plugins").exists() || portableBuf.file_name().map_or(false, |n| n != "plugins")
		{
			portableBuf.join("plugins")
		}
		else
		{
			portableBuf.clone()
		};
		updateConfigPaths(&paths.rootDir, clean, &pluginsBuf.to_string_lossy());
		paths.portablePath = portableBuf;
		paths.pluginsTargetDir = pluginsBuf;
	}

	let pluginsDir = &paths.pluginsTargetDir;
	let _ = fs::create_dir_all(pluginsDir);

	let pkgDir = pluginsDir.join("certibridge");
	let _ = fs::create_dir_all(&pkgDir);

	let pySrc = paths.srcDir.join("py");

	// deploy entrypoint to plugins/
	let entrySrc = pySrc.join("certibridge.py");
	let entryDst = pluginsDir.join("certibridge.py");
	if entrySrc.exists()
	{
		let _ = fs::copy(&entrySrc, &entryDst);
	}

	// deploy python components and utils into ordered plugins/certibridge/
	copyDirRecursive(&pySrc, &pkgDir);

	// deliver compiled c++ daemon
	let coreExeSrc = paths.rootDir.join("build/Release/certibridge_core.exe");
	if coreExeSrc.exists()
	{
		let coreExeDst = pkgDir.join("certibridge_core.exe");
		let _ = fs::copy(&coreExeSrc, &coreExeDst);
		logWithTime(&format!("delivered {} -> {}", "certibridge_core.exe".green(), coreExeDst.display()));
	}

	// deliver compiled tlsh dll
	let tlshDllSrc = paths.rootDir.join("build/Release/certibridge_tlsh.dll");
	if tlshDllSrc.exists()
	{
		let tlshDllDst = pkgDir.join("certibridge_tlsh.dll");
		let _ = fs::copy(&tlshDllSrc, &tlshDllDst);
		logWithTime(&format!("delivered {} -> {}", "certibridge_tlsh.dll".green(), tlshDllDst.display()));
	}

	logWithTime(&format!("all components delivered to IDA under {}", pluginsDir.display().to_string().cyan()));
}
