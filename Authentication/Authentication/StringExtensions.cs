using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Authentication
{
    public static class StringExtensions
    {
        const string HtmlTagPattern = "<.*?>";

        public static string TrimToLength(this string value, int length)
        {
            return value.Length > length ? value.Substring(0, length) : value;
        }

        public static string StripBeginning(this string value, CultureInfo info, params string[] list)
        {
            foreach (var s in list)
            {
                if (value.StartsWith(s, true, info))
                {
                    value = value.Substring(s.Length, (value.Length - s.Length));
                }
            }

            return value;
        }

        public static bool Validate(this string theString, bool checkForNull, bool checkIfEmpty, bool checkForCommas)
        {
            if (theString == null) return !checkForNull;

            theString = theString.Trim();
            return ((!checkIfEmpty || (theString.Length >= 1)) && (!checkForCommas || !theString.Contains(",")));
        }

        public static bool Validate(this string theString, bool checkForNull, bool checkIfEmpty, bool checkForCommas, int maxSize)
        {
            var validate = theString.Validate(checkForNull, checkIfEmpty, checkForCommas);

            if (theString == null) return validate;

            if (!validate) return false;

            return (maxSize > 0) && (theString.Length < maxSize);
        }

        public static string RandomString(int size)
        {
            var builder = new StringBuilder();
            var random = new Random();
            char ch;
            for (var i = 0; i < size; i++)
            {
                ch = Convert.ToChar(Convert.ToInt32(Math.Floor(26 * random.NextDouble() + 65)));
                builder.Append(ch);
            }

            return builder.ToString();
        }

        public static string ClearForNormalize(this string value, NormalizationForm form)
        {
            if (!string.IsNullOrEmpty(value))
            {
                value = value.Replace(":", ""); // removed for solr
                value = value.Replace("ø", "o");

                var sb = new StringBuilder();
                foreach (var c in value.Normalize(form))
                    switch (CharUnicodeInfo.GetUnicodeCategory(c))
                    {
                        case UnicodeCategory.NonSpacingMark:
                        case UnicodeCategory.SpacingCombiningMark:
                        case UnicodeCategory.EnclosingMark:
                            break;

                        default:
                            sb.Append(c);
                            break;
                    }

                return sb.ToString().ToLower();
            }

            return string.Empty;
        }

        public static string ClearForNormalize(this string value)
        {
            return value.ClearForNormalize(NormalizationForm.FormKD).Replace(" ", "").ToLower();
        }

        public static string ClearForLetter(this string value)
        {
            var @long = value.ClearForNormalize();
            if (!string.IsNullOrEmpty(@long))
            {
                var letter = @long.Substring(0, 1);
                var rgx = new Regex("[^a-zA-Z]");
                return rgx.IsMatch(letter) ? "#" : letter;
            }

            return null;
        }


        public static string StripHTML(this string inputString)
        {
            if (!string.IsNullOrEmpty(inputString))
            {
                return Regex.Replace(inputString, HtmlTagPattern, string.Empty);
            }

            return string.Empty;
        }

        public static string ConvertToHex(this string asciiString)
        {
            var hex = "";
            foreach (char c in asciiString)
            {
                int tmp = c;
                hex += String.Format("{0:x2}", (uint)Convert.ToUInt32(tmp.ToString(CultureInfo.InvariantCulture)));
            }
            return hex;
        }

        public static string ConvertFromHex(this string hexValue)
        {
            var strValue = "";
            while (hexValue.Length > 0)
            {
                strValue += Convert.ToChar(Convert.ToUInt32(hexValue.Substring(0, 2), 16)).ToString(CultureInfo.InvariantCulture);
                hexValue = hexValue.Substring(2, hexValue.Length - 2);
            }
            return strValue;
        }
    }
}
