PATH =
	(
		FileNames[
			"*.wl",
			FileNameJoin[
				{PacletObject["ToneAr/Kyber"]["Location"], "Kernel", "Source"}
			],
			Infinity
		] //
			Map[FileBaseName] //
			Map[StringJoin[ "Source`", #, "`"]&]
	);

Get[StringJoin[ "ToneAr`Kyber`", #]]& /@ {"Public`", "Private`", Splice[PATH]};