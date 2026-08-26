BeginPackage[
	"ToneAr`Kyber`FileScope`BuiltIn`",
	{
		"ToneAr`Kyber`",
		"ToneAr`Kyber`Private`",
		"Cryptography`"
		(*"Cryptography`PackageScope`",*)
		(*"Cryptography`PublicKey`PackagePrivate`"*)
	}
];
Begin["`Private`"];

Cryptography`PublicKey`PackagePrivate`inPublicKey[
	{data_?Cryptography`PackageScope`partialPublicKeyQ},
	opts : {}
] :=
	Module[{type},
		type = Lookup[data, "Type"];
		Which[
			(*Type is found and correct*)
			type === "RSA",
			Cryptography`PackageScope`makePublicKey[data, "RSA"],
			type === "EllipticCurve",
			Cryptography`PackageScope`makePublicKey[data, "EllipticCurve"],
			type === "EdwardsCurve",
			Cryptography`PackageScope`makePublicKey[data, "EdwardsCurve"],
			type === "BLSCurve",
			Cryptography`PackageScope`makePublicKey[data, "BLSCurve"],
			type === "ML-KEM",
			Cryptography`PackageScope`makePublicKey[data, "ML-KEM"],
			(*Type is found but none of the above*)
			!MissingQ[type],
			Cryptography`PackageScope`cryptoUneval[PublicKey::invtype, type],
			(*Type NOT found try Cipher or CurveName*)
			data["Cipher"] === "RSA",
			Cryptography`PackageScope`makePublicKey[data, "RSA"],
			MemberQ[data["CurveName"], Cryptography`$EdwardsCurves],
			Cryptography`PackageScope`makePublicKey[data, "EdwardsCurve"],
			!MissingQ[data["CurveName"]],
			Cryptography`PackageScope`makePublicKey[data, "EllipticCurve"],
			!MissingQ[data["PublicModulus"]],
			Cryptography`PackageScope`makePublicKey[data, "RSA"],
			True,
			Cryptography`PackageScope`cryptoUneval[]
		]
	];

Cryptography`PrivateKey`PackagePrivate`inPrivateKey[
	{data_?Cryptography`PackageScope`partialPrivateKeyQ},
	opts : {}
] :=
	Module[{type},
		type = Lookup[data, "Type"];
		Which[
			type === "RSA",
				Cryptography`PackageScope`makePrivateKey[data, "RSA"],
			type === "EllipticCurve",
				Cryptography`PackageScope`makePrivateKey[data, "EllipticCurve"],
			type === "EdwardsCurve",
				Cryptography`PackageScope`makePrivateKey[data, "EdwardsCurve"],
			type === "ML-KEM",
				Cryptography`PackageScope`makePrivateKey[data, "ML-KEM"],
			!MissingQ[type],
				Cryptography`PackageScope`cryptoUneval[PrivateKey::invtype, type],
			data["Cipher"] === "RSA",
				Cryptography`PackageScope`makePrivateKey[data, "RSA"],
			MemberQ[data["CurveName"], Cryptography`$EdwardsCurves],
				Cryptography`PackageScope`makePrivateKey[data, "EdwardsCurve"],
			!MissingQ[data["CurveName"]],
				Cryptography`PackageScope`makePrivateKey[data, "EllipticCurve"],
			!MissingQ[data["PrivateExponent"]],
				Cryptography`PackageScope`makePrivateKey[data, "RSA"],
			True,
				Cryptography`PackageScope`cryptoUneval[]
		]
	]

Cryptography`PackageScope`makePrivateKey[data_, "ML-KEM"] :=
	With[{
			cipher = StringJoin[ "ML-KEM-", ToString[data["ParameterSet"]]]
		},
		PrivateKey[
			<|
				data,
				"Cipher"          -> cipher,
				"Padding"         -> None,
				"PublicExponent"  -> None,
				"PublicModulus"   -> None,
				"PrivateExponent" -> None
			|>
		]
	];

Cryptography`PackageScope`makePublicKey[data_, "ML-KEM"] :=
	With[{
			cipher = StringJoin[ "ML-KEM-", ToString[data["ParameterSet"]]]
		},
		PublicKey[
			<|
				data,
				"Cipher"         -> cipher,
				"Padding"        -> None,
				"PublicExponent" -> None,
				"PublicModulus"  -> None
			|>
		]
	];

Cryptography`PackageScope`$PubKeyKeys =
	Replace[
		Cryptography`PublicKey`PackagePrivate`$PubKeyKeys,
		l : {Except["ParameterSet"]..} :> Join[l, {"ParameterSet"}]
	];

Cryptography`PublicKey`PackagePrivate`$PubKeyKeys =
	Cryptography`PackageScope`$PubKeyKeys;

Cryptography`PrivateKey`PackagePrivate`$PrKeyKeys =
	Replace[
		Cryptography`PrivateKey`PackagePrivate`$PrKeyKeys,
		l : {Except["ParameterSet"]..} :> Join[l, {"ParameterSet"}]
	];

Unprotect[GenerateAsymmetricKeyPair, Encrypt, Decrypt];

Encrypt[
	pubKey : PublicKey[KeyValuePattern[{"Type" -> "ML-KEM"}]],
	expr_,
	opts : OptionsPattern[Encrypt]
] :=
	KyberEncrypt[pubKey, expr, opts];

Decrypt[
	pvtKey : PrivateKey[KeyValuePattern[{"Type" -> "ML-KEM"}]],
	expr_,
	opts : OptionsPattern[Decrypt]
] :=
	KyberDecrypt[pvtKey, expr, opts];

GenerateAsymmetricKeyPair // Options =
	Join[Options[GenerateAsymmetricKeyPair], {"ParameterSet" -> 768}];
GenerateAsymmetricKeyPair[
	"Method" -> ("ML-KEM" | "Kyber"),
	OptionsPattern[{"ParameterSet" -> 768}]
] :=
	KyberKeyGen[OptionValue["ParameterSet"]];
GenerateAsymmetricKeyPair["ML-KEM" | "Kyber", OptionsPattern[]] :=
	KyberKeyGen[OptionValue["ParameterSet"]];

DownValues[GenerateAsymmetricKeyPair] =
	SortBy[DownValues[GenerateAsymmetricKeyPair], FreeQ["ML-KEM"]];
DownValues[Encrypt] = SortBy[DownValues[Encrypt], FreeQ["ML-KEM"]];
DownValues[Decrypt] = SortBy[DownValues[Decrypt], FreeQ["ML-KEM"]];

Protect[GenerateAsymmetricKeyPair, Encrypt, Decrypt];

End[];
EndPackage[];