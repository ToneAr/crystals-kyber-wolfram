BeginPackage[
	"ToneAr`Kyber`FileScope`Objects`",
	{"ToneAr`Kyber`", "ToneAr`Kyber`Private`", "Cryptography`"}
];
Begin["`Private`"];

Protect[PrivateKey, PublicKey];

Cryptography`summaryBoxes`PackagePrivate`PrivateKeyMakeBoxes[
	PrivateKey[
		data :
			KeyValuePattern[
				{
					_["Type", "ML-KEM"] | _["Cipher", "ML-KEM"],
					_[
						"ParameterSet",
						pSet : (512 | 768 | 1024) /; IntegerQ[Unevaluated[pSet]]
					],
					_[
						"PublicByteArray",
						pubBa_ByteArray /; MatchQ[Unevaluated[pubBa], _ByteArray]
					],
					_[
						"PrivateByteArray",
						pvtBa_ByteArray /; MatchQ[Unevaluated[pvtBa], _ByteArray]
					]
				}
			]
	],
	form_
] :=
	Module[{main, extra},
		main =
			{
				BoxForm`SummaryItem[{"Type: ", "ML-KEM"}],
				BoxForm`SummaryItem[{"Parameter set: ", ToString[pSet]}],
				BoxForm`SummaryItem[
					{
						"Private key size: ",
						Cryptography`summaryBoxes`PackagePrivate`getLength[pvtBa]
					}
				]
			};
		extra =
			{
				BoxForm`SummaryItem[
					{
						"Public key size: ",
						Cryptography`summaryBoxes`PackagePrivate`getLength[pubBa]
					}
				]
			};
		BoxForm`ArrangeSummaryBox[
			PrivateKey,
			PrivateKey[data],
			Cryptography`summaryBoxes`PackagePrivate`makeKeyIcon[data, 100],
			main,
			extra,
			form
		]
	];

Cryptography`summaryBoxes`PackagePrivate`PublicKeyMakeBoxes[
	PublicKey[
		data :
			KeyValuePattern[
				{
					_["Type", "ML-KEM"] | _["Cipher", "ML-KEM"],
					_[
						"ParameterSet",
						pSet : (512 | 768 | 1024) /; IntegerQ[Unevaluated[pSet]]
					],
					_[
						"PublicByteArray",
						pubBa_ByteArray /; MatchQ[Unevaluated[pubBa], _ByteArray]
					]
				}
			]
	],
	form_
] :=
	Module[{main, extra},
		main =
			{
				BoxForm`SummaryItem[{"Type: ", "ML-KEM"}],
				BoxForm`SummaryItem[{"Parameter set: ", ToString[pSet]}],
				BoxForm`SummaryItem[
					{
						"Public key size: ",
						Cryptography`summaryBoxes`PackagePrivate`getLength[pubBa]
					}
				]
			};
		extra = {};
		BoxForm`ArrangeSummaryBox[
			PublicKey,
			PublicKey[data],
			Cryptography`summaryBoxes`PackagePrivate`makeKeyIcon[data, 100],
			main,
			extra,
			form
		]
	];

Unprotect[PrivateKey, PublicKey];

MakeBoxes[
	EncapsulatedKey[
		data :
			KeyValuePattern[
				{
					_["Type", "ML-KEM"] | _["Cipher", "ML-KEM"],
					_[
						"ParameterSet",
						pSet : (512 | 768 | 1024) /; IntegerQ[Unevaluated[pSet]]
					],
					_[
						"CipherText",
						cText_ByteArray /; MatchQ[Unevaluated[cText], _ByteArray]
					]
				}
			]
	],
	form_
] ^:=
	Module[{main, extra},
		main =
			{
				BoxForm`SummaryItem[{"Type: ", "ML-KEM"}],
				BoxForm`SummaryItem[{"Parameter set: ", ToString[pSet]}],
				BoxForm`SummaryItem[
					{
						"Cipher text size: ",
						Cryptography`summaryBoxes`PackagePrivate`getLength[cText]
					}
				]
			};
		extra = {};
		BoxForm`ArrangeSummaryBox[
			EncapsulatedKey,
			obj,
			Cryptography`summaryBoxes`PackagePrivate`makeKeyIcon[data, 100],
			main,
			extra,
			form
		]
	];

EncapsulatedKey[assoc_Association][key_] :=
	Lookup[assoc, key, Missing["KeyAbsent", key]];
EncapsulatedKey[assoc_Association]["Properties"] := Keys[assoc];

$EncapsulatedKeyProperties = {"Type", "ParameterSet", "CipherText"}

End[];
EndPackage[];