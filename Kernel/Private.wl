BeginPackage["ToneAr`Kyber`Private`", {"ToneAr`Kyber`"}];

$kyberLibrary = None;

$kyberKeygen = None;

$kyberEncapsulate = None;

$kyberDecapsulate = None;

kyberPlatformConfig[] :=
	Switch[$OperatingSystem,
		"Windows",
			<|
				"CC"           -> "cl",
				"CompileFlags" -> "/O2 /nologo /c",
				"IncludeFlag"  -> "/I",
				"OutputFlag"   -> "/Fo",
				"DefineFlag"   -> "/D",
				"ObjectExt"    -> ".obj",
				"LibExt"       -> ".dll",
				"LinkCmd"      -> "cl /nologo /LD /Fe\"~TARGET~\" ~OBJS~ advapi32.lib"
			|>,
		"MacOSX",
			<|
				"CC"           -> "cc",
				"CompileFlags" -> "-O2 -Wall -fPIC -c",
				"IncludeFlag"  -> "-I",
				"OutputFlag"   -> "-o ",
				"DefineFlag"   -> "-D",
				"ObjectExt"    -> ".o",
				"LibExt"       -> ".dylib",
				"LinkCmd"      -> "cc -dynamiclib -o \"~TARGET~\" ~OBJS~"
			|>,
		_,
			<|
				"CC"           -> "gcc",
				"CompileFlags" -> "-O2 -Wall -fPIC -c",
				"IncludeFlag"  -> "-I",
				"OutputFlag"   -> "-o ",
				"DefineFlag"   -> "-D",
				"ObjectExt"    -> ".o",
				"LibExt"       -> ".so",
				"LinkCmd"      -> "gcc -shared -o \"~TARGET~\" ~OBJS~"
			|>
	];

kyberCompileSource[cfg_, includes_, defines_, srcPath_, objPath_] :=
	Module[{cmd, rc},
		cmd =
			StringTemplate[
				StringJoin[
					"`CC` `CompileFlags` `Includes` `Defines` `OutputFlag``ObjPath` ",
					"`SrcPath`"
				]
			][
				<|
					"CC"           -> cfg["CC"],
					"CompileFlags" -> cfg["CompileFlags"],
					"Includes"     -> StringRiffle[
						Map[StringJoin[ cfg["IncludeFlag"], "\"", #, "\""]&, includes],
						" "
					],
					"Defines"      -> StringRiffle[
						Map[StringJoin[ cfg["DefineFlag"], #]&, defines],
						" "
					],
					"OutputFlag"   -> cfg["OutputFlag"],
					"ObjPath"      -> StringJoin[ "\"", objPath, "\""],
					"SrcPath"      -> StringJoin[ "\"", srcPath, "\""]
				|>
			];
		rc = Run[cmd];
		If[rc =!= 0, Message[KyberKeyGen::buildfail, cmd]; Return[$Failed]];
		objPath
	];

kyberBuildLibrary[] :=
	Module[{
			pacletDir,
			buildDir,
			libTarget,
			kyberRef,
			wolframInc,
			cfg,
			includes,
			sharedSrcs,
			kSrcs,
			objs,
			obj,
			cmd,
			rc
		},
		cfg = kyberPlatformConfig[];
		pacletDir = PacletObject["ToneAr/Kyber"]["Location"];
		buildDir = FileNameJoin[{pacletDir, "build"}];
		libTarget =
			FileNameJoin[
				{
					pacletDir,
					"LibraryResources",
					$SystemID,
					StringJoin[ "kyber_link", cfg["LibExt"]]
				}
			];
		kyberRef = FileNameJoin[{pacletDir, "kyber", "ref"}];
		wolframInc =
			FileNameJoin[
				{$InstallationDirectory, "SystemFiles", "IncludeFiles", "C"}
			];
		includes = {wolframInc, kyberRef};
		(* Ensure directories *)
		Map[
			Quiet @ CreateDirectory[#, CreateIntermediateDirectories -> True]&,
			{
				FileNameJoin[{buildDir, "shared"}],
				FileNameJoin[{buildDir, "kyber512"}],
				FileNameJoin[{buildDir, "kyber768"}],
				FileNameJoin[{buildDir, "kyber1024"}],
				DirectoryName[libTarget]
			}
		];
		sharedSrcs = {"fips202.c", "randombytes.c"};
		kSrcs =
			{
				"cbd.c",
				"indcpa.c",
				"kem.c",
				"ntt.c",
				"poly.c",
				"polyvec.c",
				"reduce.c",
				"symmetric-shake.c",
				"verify.c"
			};
		objs = {};
		(* Compile shared sources (K-independent, once) *)
		Do[
			obj =
				kyberCompileSource[
					cfg,
					includes,
					{"KYBER_K=3"},
					FileNameJoin[{kyberRef, s}],
					FileNameJoin[
						{buildDir, "shared", StringReplace[s, ".c" -> cfg["ObjectExt"]]}
					]
				];
			If[obj === $Failed, Return[$Failed]];
			AppendTo[objs, obj],
			{s, sharedSrcs}
		];
		(* Compile K-dependent sources for each security level *)
		Do[
			With[{k = spec[[1]], tag = spec[[2]]},
				Do[
					obj =
						kyberCompileSource[
							cfg,
							includes,
							{StringJoin[ "KYBER_K=", ToString[k]]},
							FileNameJoin[{kyberRef, s}],
							FileNameJoin[
								{buildDir, tag, StringReplace[s, ".c" -> cfg["ObjectExt"]]}
							]
						];
					If[obj === $Failed, Return[$Failed]];
					AppendTo[objs, obj],
					{s, kSrcs}
				]
			],
			{spec, {{2, "kyber512"}, {3, "kyber768"}, {4, "kyber1024"}}}
		];
		(* Compile LibraryLink wrapper *)
		obj =
			kyberCompileSource[
				cfg,
				includes,
				{},
				FileNameJoin[{pacletDir, "src", "kyber_link.c"}],
				FileNameJoin[{buildDir, StringJoin[ "kyber_link", cfg["ObjectExt"]]}]
			];
		If[obj === $Failed, Return[$Failed]];
		AppendTo[objs, obj];
		(* Link into shared library *)
		cmd =
			StringReplace[
				cfg["LinkCmd"],
				{
					"~TARGET~" -> libTarget,
					"~OBJS~"   -> StringRiffle[
						Map[StringJoin[ "\"", #, "\""]&, objs],
						" "
					]
				}
			];
		rc = Run[cmd];
		If[rc =!= 0, Message[KyberKeyGen::buildfail, cmd]; Return[$Failed]];
		libTarget
	];

kyberLoadLibrary[] :=
	Module[{libPath, lib},
		libPath =
			FileNameJoin[
				{
					PacletObject["ToneAr/Kyber"]["Location"],
					"LibraryResources",
					$SystemID,
					"kyber_link"
				}
			];
		lib = FindLibrary[libPath];
		(* If the library doesn't exist, build it *)
		If[lib === $Failed,
			kyberBuildLibrary[];
			lib = FindLibrary[libPath];
		];
		If[lib === $Failed,
			Message[KyberKeyGen::nolib, libPath];
			Return[$Failed]
		];
		$kyberLibrary = lib;
		$kyberKeygen =
			LibraryFunctionLoad[
				lib,
				"kyber_keygen",
				{Integer}, (* securityLevel *)
				"DataStore"
			];
		$kyberEncapsulate =
			LibraryFunctionLoad[
				lib,
				"kyber_encapsulate",
				{{Integer, 1}, Integer}, (* publicKey, securityLevel *)
				"DataStore"
			];
		$kyberDecapsulate =
			LibraryFunctionLoad[
				lib,
				"kyber_decapsulate",
				{
					{Integer, 1},
					{Integer, 1},
					Integer
				}, (* ciphertext, secretKey, securityLevel *)
				{Integer, 1}
			];
		lib
	];

kyberEnsureLoaded[] := If[$kyberLibrary === None, kyberLoadLibrary[]];

securityLevelQ[n_] := MemberQ[{512, 768, 1024}, n];

securityLevelFromString[s_String] :=
	Switch[s,
		"Kyber512" | "512",
			512,
		"Kyber768" | "768",
			768,
		"Kyber1024" | "1024",
			1024,
		_,
			$Failed
	];

normalizeSecurityLevel[n_Integer] /; securityLevelQ[n] := n;
normalizeSecurityLevel[s_String] := securityLevelFromString[s];
normalizeSecurityLevel[___] := $Failed;

EndPackage[];