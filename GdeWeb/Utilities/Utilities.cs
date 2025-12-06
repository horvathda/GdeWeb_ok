using MudBlazor;
using System.ComponentModel;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using MudBlazor.Charts;
using System.Globalization;

namespace GdeWeb.Utilities
{
    public static class Utilities
    {
        public static string EncryptPassword(string password)
        {
            SHA512? provider = SHA512.Create();
            string salt = "Gd3R@nd0mS@lt";
            byte[] code = Encoding.UTF32.GetBytes(salt + password);
            string code_string = string.Join(" ", code);
            byte[] bytes = provider.ComputeHash(code);
            string bytes_string = string.Join(" ", bytes);
            string converted = BitConverter.ToString(bytes).Replace("-", "").ToLower();
            return converted;
        }

        public static string GeneratePassword(int lengthOfPassword, int numberOfNonAlphanumericCharacters)
        {
            // to generate more complex password, change valid string value
            string valid = "abcdefghijklmnozABCDEFGHIJKLMNOZ1234567890!@#$%^&*()=";

            StringBuilder strB = new StringBuilder(100);
            Random random = new Random();

            while (Regex.Matches(strB.ToString(), "[!@#$%^&*()=]").Count != numberOfNonAlphanumericCharacters)
            {
                strB.Clear();
                while (strB.ToString().Length < lengthOfPassword)
                {
                    strB.Append(valid[random.Next(valid.Length)]);
                }
            }

            return strB.ToString();
        }

        public static string ProcessException(Exception ex)
        {
            string message = ex.Message.ToLower();

            if (message.Contains("grpc") || message.Contains("debug") || message.Contains("failed") || message.Contains("status") || message.Contains("http"))
            {
                return "Váratlan hiba történt a művelet során!";
            }
            else
            {
                return ex.Message;
            }
        }
    }
}