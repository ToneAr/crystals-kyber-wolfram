BeginPackage["ToneAr`Kyber`"];

(* ---- Constants ---- *)

$KyberSecurityLevels = {512, 768, 1024};

(* ---- Messages ---- *)

EncapsulatedKey;
KyberEncrypt;
KyberDecrypt;
KyberKeyGen::nolib = "Could not load the Kyber shared library at `1`.";
KyberKeyGen::buildfail = "Build step failed. Command: `1`";
KyberKeyGen::badlvl = "Security level `1` is not valid. Use 512, 768, or 1024.";

KyberEncapsulate::badlvl = KyberKeyGen::badlvl;
KyberEncapsulate::badpk =
	StringJoin[
		"Public key must be a list of integers with correct length for the given ",
		"security level."
	];

KyberDecapsulate::badlvl = KyberKeyGen::badlvl;
KyberDecapsulate::badct =
	StringJoin[
		"Ciphertext must be a list of integers with correct length for the given ",
		"security level."
	];
KyberDecapsulate::badsk =
	StringJoin[
		"Secret key must be a list of integers with correct length for the given ",
		"security level."
	];

EndPackage[];