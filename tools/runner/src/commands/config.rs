#![allow(non_snake_case)]

use crate::config::{updateConfigPaths, WorkspacePaths};

pub fn run(paths: &mut WorkspacePaths, args: &[String])
{
	let input = if !args.is_empty()
	{
		args[0].clone()
	}
	else
	{
		dialoguer::Input::<String>::new()
			.with_prompt("Enter your IDA directory or plugins directory")
			.interact_text()
			.unwrap_or_default()
	};

	let clean = input.trim();
	if !clean.is_empty()
	{
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
}
