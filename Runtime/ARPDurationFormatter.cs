// SPDX-FileCopyrightText: 2026 cfm-miku-en
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Globalization;

namespace ARP
{
    public static class ARPDurationFormatter
    {
        public const string Placeholder = "{{long}}";

        public static string Format(double amount, ARPTimeUnit unit)
        {
            var totalMinutes = ToMinutes(amount, unit);

            if (totalMinutes <= 0) return "0 minutes";

            if (totalMinutes % 1440 == 0) return Pluralize(totalMinutes / 1440, "day");
            if (totalMinutes % 60 == 0) return Pluralize(totalMinutes / 60, "hour");
            return Pluralize(totalMinutes, "minute");
        }

        public static string Apply(string template, double amount, ARPTimeUnit unit)
        {
            if (string.IsNullOrEmpty(template)) return string.Empty;
            return template.Replace(Placeholder, Format(amount, unit));
        }

        public static double ToHours(double amount, ARPTimeUnit unit)
        {
            switch (unit)
            {
                case ARPTimeUnit.Minutes: return amount / 60.0;
                case ARPTimeUnit.Hours: return amount;
                case ARPTimeUnit.Days: return amount * 24.0;
                default: throw new ArgumentOutOfRangeException(nameof(unit));
            }
        }

        private static long ToMinutes(double amount, ARPTimeUnit unit)
        {
            switch (unit)
            {
                case ARPTimeUnit.Minutes: return (long)Math.Round(amount);
                case ARPTimeUnit.Hours: return (long)Math.Round(amount * 60);
                case ARPTimeUnit.Days: return (long)Math.Round(amount * 1440);
                default: throw new ArgumentOutOfRangeException(nameof(unit));
            }
        }

        private static string Pluralize(long value, string unit) =>
            value == 1
                ? "1 " + unit
                : value.ToString(CultureInfo.InvariantCulture) + " " + unit + "s";
    }
}
