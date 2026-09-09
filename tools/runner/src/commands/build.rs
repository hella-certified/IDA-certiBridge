#![allow(non_snake_case)]

use colored::Colorize;
use crate::config::WorkspacePaths;
use crate::utils::process::{logWithTime, runCommand};

pub fn run(paths: &mut WorkspacePaths, _args: &[String])
{
	logWithTime(&"configuring CMake build for C++ core...".cyan().to_string());
	if !runCommand("cmake", &["-B", "build", "-S", "."], &paths.rootDir)
	{
		logWithTime(&"CMake configuration failed".red().to_string());
		return;
	}

	logWithTime(&"building Release target...".cyan().to_string());
	if runCommand("cmake", &["--build", "build", "--config", "Release"], &paths.rootDir)
	{
		logWithTime(&"C++ core daemon built successfully".green().to_string());
		logWithTime(&"delivering all components directly to IDA plugins...".cyan().to_string());
		crate::commands::deploy::run(paths, &[]);
	}
	else
	{
		logWithTime(&"build failed".red().to_string());
	}
}
