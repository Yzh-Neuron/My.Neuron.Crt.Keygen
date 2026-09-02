using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using System.Text;

namespace NeuronKeyGenWasm
{
    public static class LicenseFileGeneratorBc
    {
        // 从你的RSAKeyValue XML提取各字段Base64
        private const string ModulusB64 = "65DpdTq9sDz3CltqccilQcOliqrNbnw7k9upnS2VntwP4qtt3j5LpYy+a5OLQQsF5RKtmcCT93Qgi24loyFRiUyb27S5toVs+mcvRPfKnPs0eLv116FfwuzZNTC30s+7KlGi2TWGKuALNKij/onW87itAWVqo00pUzQ917zpaMQdphwC0BXrEPLTvFn6ETZ2SguOYHkxK7MqkEf/K+ysEM8QLQCoxuTpYYebT+ztmeyiTHKvSqKsN1Oe2Z1HREtaqZ4dSnNvo15/Jh0nLmT865sL7q4B4/hNGRw/JDPraW/XmAsd07wDykqYeANsrIoWCrdHvNPF/HbAnsZA7D6nHQ==";
        private const string ExponentB64 = "AQAB";
        private const string PB64 = "/mJpBvRaNOE+RzqAbeh2EKt5S7GrSZGfkLqBmAvt3qN3KPdnRHw72mTtSn4NoAwRMZYx03j8vABkfxx5K78iu87tuWny6R+RLAGE7nv03Zh6tw7IfTzW4PHGsaIGKshI8n8/HleXi2RWOVom7skL1Y2il1nrnIqoZXa1aIsoUOs=";
        private const string QB64 = "7Q/n7FQnuM7496lLcdZG6k9BsjKut8i0Y1NJ6aFkK86yoc9M7u7FVNv7qAAmc/6yWrn/LhOpki9FccDkkEFpVuj0PJVYfS1Pn1Af3QTI9Ei51iJ5Qs7lLFEE6ZIaWImkJCfzyTIvPzbQRms518igWCdkvgxCL9l6bYzB8PO1phc=";
        private const string DB64 = "fyqMjSd3zVMr/aBZ9zDc3YKztAb+vX09YFV93AcGtWqQ/MmUlxxEFAvFpCdTTnqX5RDPPKg0eKptAzgkA0tyS89aeCG4+6pNqWPYpb+q1lHaAq9dSNmp632WyFsTcS+JF5BYfC+jzTODeRrs5PUeYBW693z7M0rtWyhhljw6OL5VAZbGPGeMqhK5iKo11X4VLj0MsqTXWIywzYJM8PKi+xS3QUFXPZLTINblxcmnUNxaLQJ7u4soa7SS4xCeqqTxPrNW9wCXAeT8FmAfBcCvwH6SPsnZRdVIlPaVeX3QfJiudZYSwJwsEaHH329kgi53RQKlrVcORchRBb1zu50tlQ==";
        private const string DPB64 = "IvQItGDs6Cku8oCSVwfC+UVmdEUkYQZ2Y1+NIQQ6mgXiAKoF8X4Uh0yo4jxxyNT/o82caQ9NwtNW+7RA3gb0UdP8DCcHroqc2uwWhOJZYf1qly6b08GBUQVHpO67ZDOC+ncLiDLG6utNgbHmeZb8XkqI1b0QR8ExpEdsY8IDNyM=";
        private const string DQB64 = "JQai9qp+OcM555Stj+4jzVzrqeV4nIPgiNLtbGwktSLni5ZRMdBhScvCFo9PcjaJrNn4HT488fQoKIg0KsPMrCJeY0gANizpjrx4/ZBNwrnJLMTdo62k5bMRzVlgfAujc3I6BWatMnZhOV5t/mH7iUk91uEbRVX2ZT3i3Ltz16k=";
        private const string InverseQB64 = "WVmihIfYLeCpOL9bERHx6fOiMg5UWx+ADZ27VE7N9SwS1znRc6PIASwExiPZr/w5+40VU7qJeX6cjiTHk8LMkjbeVZyeTEPmGtwVQNp305qGSQ2Yl8vZzOQ/5pj51KR5+2OzCw0DT7FR0vXTpa/5z/5rb6D3vX8hyGWCyQYDwts=";

        private static readonly RsaPrivateCrtKeyParameters _privateKey;

        static LicenseFileGeneratorBc()
        {
            BigInteger mod = new BigInteger(1, Convert.FromBase64String(ModulusB64));
            BigInteger exp = new BigInteger(1, Convert.FromBase64String(ExponentB64));
            BigInteger p = new BigInteger(1, Convert.FromBase64String(PB64));
            BigInteger q = new BigInteger(1, Convert.FromBase64String(QB64));
            BigInteger d = new BigInteger(1, Convert.FromBase64String(DB64));
            BigInteger dp = new BigInteger(1, Convert.FromBase64String(DPB64));
            BigInteger dq = new BigInteger(1, Convert.FromBase64String(DQB64));
            BigInteger invQ = new BigInteger(1, Convert.FromBase64String(InverseQB64));

            _privateKey = new RsaPrivateCrtKeyParameters(mod, exp, d, p, q, dp, dq, invQ);
        }

        /// <summary>
        /// RSA‑PKCS1‑SHA256签名，返回Base64签名字符串，和原版System.Security.Cryptography输出100%兼容
        /// Blazor‑Wasm可直接调用，无平台异常
        /// </summary>
        /// <param name="machineCode">机器码</param>
        /// <returns>base64签名</returns>
        public static string Sign(string machineCode)
        {
            // RSADigestSigner = RSASSA‑PKCS1‑v1_5，对应 .NET RSASignaturePadding.Pkcs1
            var signer = new RsaDigestSigner(new Sha256Digest());
            signer.Init(true, _privateKey);

            byte[] data = Encoding.UTF8.GetBytes(machineCode);
            signer.BlockUpdate(data, 0, data.Length);
            byte[] signatureBytes = signer.GenerateSignature();

            return Convert.ToBase64String(signatureBytes);
        }

        /// <summary>
        /// 签名并保存文件，仅控制台使用；Wasm浏览器不可调用File.WriteAllText
        /// </summary>
        public static void SignToFile(string machineCode, string outputPath)
        {
            string sig = Sign(machineCode);
            System.IO.File.WriteAllText(outputPath, sig);
        }
    }
}
