using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MinimalFirewall
{
    public sealed record TrustedPublisherEntry(
        string Sha256Thumbprint,
        string DisplayName,
        string Subject,
        bool IsLegacy = false,
        string? LegacyValue = null)
    {
        public override string ToString() => IsLegacy
            ? $"{DisplayName} [legacy name-only entry, disabled]"
            : $"{DisplayName} [SHA-256 {Sha256Thumbprint[..12]}…]";
    }

    public sealed class PublisherWhitelistService
    {
        private readonly string _configPath;
        private readonly Dictionary<string, TrustedPublisherEntry> _trustedPublishers =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _legacyPublisherNames =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly object _lock = new();

        public PublisherWhitelistService()
            : this(ConfigPathManager.GetConfigPath("trusted_publishers.json"))
        {
        }

        internal PublisherWhitelistService(string configPath)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(configPath);
            _configPath = configPath;
            Load();
        }

        private void Load()
        {
            lock (_lock)
            {
                try
                {
                    if (!File.Exists(_configPath))
                    {
                        return;
                    }

                    string json = File.ReadAllText(_configPath);
                    if (string.IsNullOrWhiteSpace(json))
                    {
                        return;
                    }

                    using JsonDocument document = JsonDocument.Parse(json);
                    if (document.RootElement.ValueKind == JsonValueKind.Array)
                    {
                        // Legacy schema stored publisher CN/name strings. Keep them visible so
                        // users can remove them, but never treat a display name as signer identity.
                        foreach (JsonElement item in document.RootElement.EnumerateArray())
                        {
                            if (item.ValueKind == JsonValueKind.String)
                            {
                                string? legacyName = item.GetString();
                                if (!string.IsNullOrWhiteSpace(legacyName))
                                {
                                    _legacyPublisherNames.Add(legacyName);
                                }
                            }
                        }

                        return;
                    }

                    if (document.RootElement.ValueKind != JsonValueKind.Object)
                    {
                        return;
                    }

                    var loaded = JsonSerializer.Deserialize(
                        json,
                        WhitelistJsonContext.Default.PublisherWhitelistDocument);

                    if (loaded?.Certificates != null)
                    {
                        foreach (TrustedPublisherCertificate certificate in loaded.Certificates)
                        {
                            if (TryNormalizeSha256Thumbprint(certificate.Sha256Thumbprint, out string normalized)
                                && !string.IsNullOrWhiteSpace(certificate.DisplayName)
                                && !string.IsNullOrWhiteSpace(certificate.Subject))
                            {
                                _trustedPublishers[normalized] = new TrustedPublisherEntry(
                                    normalized,
                                    certificate.DisplayName.Trim(),
                                    certificate.Subject.Trim());
                            }
                        }
                    }

                    if (loaded?.LegacyNames != null)
                    {
                        foreach (string legacyName in loaded.LegacyNames)
                        {
                            if (!string.IsNullOrWhiteSpace(legacyName))
                            {
                                _legacyPublisherNames.Add(legacyName);
                            }
                        }
                    }
                }
                catch (Exception ex) when (ex is IOException
                    or UnauthorizedAccessException
                    or JsonException
                    or CryptographicException)
                {
                    Debug.WriteLine($"[ERROR] Failed to load publisher whitelist: {ex.Message}");
                    _trustedPublishers.Clear();
                    _legacyPublisherNames.Clear();
                }
            }
        }

        private static bool TryNormalizeSha256Thumbprint(string? value, out string normalized)
        {
            normalized = string.Empty;
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            string compact = value.Replace(":", string.Empty, StringComparison.Ordinal)
                .Replace(" ", string.Empty, StringComparison.Ordinal)
                .Trim();

            if (compact.Length != 64 || compact.Any(character => !Uri.IsHexDigit(character)))
            {
                return false;
            }

            normalized = compact.ToUpperInvariant();
            return true;
        }

        private void Save()
        {
            lock (_lock)
            {
                try
                {
                    var document = new PublisherWhitelistDocument
                    {
                        Version = 2,
                        Certificates = _trustedPublishers.Values
                            .OrderBy(entry => entry.DisplayName, StringComparer.OrdinalIgnoreCase)
                            .Select(entry => new TrustedPublisherCertificate
                            {
                                Sha256Thumbprint = entry.Sha256Thumbprint,
                                DisplayName = entry.DisplayName,
                                Subject = entry.Subject
                            })
                            .ToList(),
                        LegacyNames = _legacyPublisherNames.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToList()
                    };

                    string json = JsonSerializer.Serialize(
                        document,
                        WhitelistJsonContext.Default.PublisherWhitelistDocument);
                    string? directory = Path.GetDirectoryName(_configPath);
                    if (!string.IsNullOrEmpty(directory))
                    {
                        Directory.CreateDirectory(directory);
                    }

                    string tempPath = _configPath + ".tmp";
                    File.WriteAllText(tempPath, json);
                    File.Move(tempPath, _configPath, overwrite: true);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
                {
                    Debug.WriteLine($"[ERROR] Failed to save publisher whitelist: {ex.Message}");
                }
            }
        }

        public List<TrustedPublisherEntry> GetTrustedPublishers()
        {
            lock (_lock)
            {
                var entries = _trustedPublishers.Values.ToList();
                entries.AddRange(_legacyPublisherNames.Select(name =>
                    new TrustedPublisherEntry(string.Empty, GetLegacyDisplayName(name), string.Empty, true, name)));

                return entries
                    .OrderBy(entry => entry.DisplayName, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(entry => entry.Sha256Thumbprint, StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }
        }

        private static string GetLegacyDisplayName(string value)
        {
            const string cnPrefix = "CN=";
            int cnStart = value.IndexOf(cnPrefix, StringComparison.OrdinalIgnoreCase);
            if (cnStart < 0)
            {
                return value;
            }

            cnStart += cnPrefix.Length;
            int cnEnd = value.IndexOf(',', cnStart);
            string commonName = cnEnd < 0
                ? value.Substring(cnStart).Trim()
                : value.Substring(cnStart, cnEnd - cnStart).Trim();

            return string.IsNullOrEmpty(commonName) ? value : commonName;
        }

        public bool IsCertificateTrusted(string sha256Thumbprint)
        {
            if (!TryNormalizeSha256Thumbprint(sha256Thumbprint, out string normalized))
            {
                return false;
            }

            lock (_lock)
            {
                return _trustedPublishers.ContainsKey(normalized);
            }
        }

        public void AddTrustedCertificate(string sha256Thumbprint, string displayName, string subject)
        {
            if (!TryNormalizeSha256Thumbprint(sha256Thumbprint, out string normalized)
                || string.IsNullOrWhiteSpace(displayName)
                || string.IsNullOrWhiteSpace(subject))
            {
                return;
            }

            lock (_lock)
            {
                if (!_trustedPublishers.ContainsKey(normalized))
                {
                    _trustedPublishers.Add(normalized, new TrustedPublisherEntry(
                        normalized,
                        displayName.Trim(),
                        subject.Trim()));
                    Save();
                }
            }
        }

        public void Remove(TrustedPublisherEntry entry)
        {
            ArgumentNullException.ThrowIfNull(entry);

            lock (_lock)
            {
                bool removed = entry.IsLegacy
                    ? _legacyPublisherNames.Remove(entry.LegacyValue ?? entry.DisplayName)
                    : TryNormalizeSha256Thumbprint(entry.Sha256Thumbprint, out string normalized)
                        && _trustedPublishers.Remove(normalized);

                if (removed)
                {
                    Save();
                }
            }
        }
    }

    internal sealed class PublisherWhitelistDocument
    {
        public int Version { get; set; } = 2;
        public List<TrustedPublisherCertificate> Certificates { get; set; } = [];
        public List<string> LegacyNames { get; set; } = [];
    }

    internal sealed class TrustedPublisherCertificate
    {
        public string Sha256Thumbprint { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;
    }

    [JsonSourceGenerationOptions(WriteIndented = true)]
    [JsonSerializable(typeof(PublisherWhitelistDocument))]
    internal partial class WhitelistJsonContext : JsonSerializerContext { }
}
