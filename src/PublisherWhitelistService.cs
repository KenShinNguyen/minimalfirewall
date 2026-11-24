using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MinimalFirewall
{
    public class PublisherWhitelistService
    {
        private const int CurrentDocumentVersion = 2;

        private readonly string _configPath;
        private readonly Dictionary<string, PublisherCertificateIdentity> _trustedPublishers =
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

                    using var parsed = JsonDocument.Parse(json);
                    if (parsed.RootElement.ValueKind == JsonValueKind.Array)
                    {
                        // Version 1 stored only publisher CN strings. They cannot be
                        // safely upgraded to a certificate identity, so preserve them
                        // for user review but never use them for auto-allow matching.
                        var legacyNames = JsonSerializer.Deserialize(
                            json,
                            WhitelistJsonContext.Default.HashSetString);

                        if (legacyNames != null)
                        {
                            foreach (string? name in legacyNames)
                            {
                                if (!string.IsNullOrWhiteSpace(name))
                                {
                                    _legacyPublisherNames.Add(name.Trim());
                                }
                            }

                            Save();
                        }

                        return;
                    }

                    if (parsed.RootElement.ValueKind != JsonValueKind.Object)
                    {
                        return;
                    }

                    var loaded = JsonSerializer.Deserialize(
                        json,
                        WhitelistJsonContext.Default.PublisherWhitelistDocument);

                    if (loaded?.Version != CurrentDocumentVersion)
                    {
                        Debug.WriteLine("[PublisherWhitelist] Unsupported whitelist document version; no entries were loaded.");
                        return;
                    }

                    foreach (PublisherCertificateIdentity? publisher in loaded.Publishers ?? [])
                    {
                        if (publisher == null ||
                            string.IsNullOrWhiteSpace(publisher.Subject) ||
                            string.IsNullOrWhiteSpace(publisher.Issuer))
                        {
                            continue;
                        }

                        string? thumbprint = NormalizeSha256Thumbprint(publisher.Sha256Thumbprint);
                        if (thumbprint == null)
                        {
                            continue;
                        }

                        _trustedPublishers.TryAdd(
                            thumbprint,
                            publisher with { Sha256Thumbprint = thumbprint });
                    }

                    foreach (string? legacyName in loaded.LegacyNames ?? [])
                    {
                        if (!string.IsNullOrWhiteSpace(legacyName))
                        {
                            _legacyPublisherNames.Add(legacyName.Trim());
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[ERROR] Failed to load publisher whitelist: {ex.Message}");
                }
            }
        }

        public List<PublisherWhitelistEntry> GetTrustedPublishers()
        {
            lock (_lock)
            {
                var entries = _trustedPublishers.Values
                    .Select(publisher => new PublisherWhitelistEntry(
                        publisher.Sha256Thumbprint,
                        publisher.Subject,
                        publisher.Issuer,
                        IsLegacy: false))
                    .Concat(_legacyPublisherNames.Select(name => new PublisherWhitelistEntry(
                        string.Empty,
                        name,
                        string.Empty,
                        IsLegacy: true)));

                return entries
                    .OrderBy(entry => entry.DisplayName, StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }
        }

        public bool IsTrusted(PublisherCertificateIdentity? publisherIdentity)
        {
            if (publisherIdentity == null)
            {
                return false;
            }

            string? thumbprint = NormalizeSha256Thumbprint(publisherIdentity.Sha256Thumbprint);
            if (thumbprint == null)
            {
                return false;
            }

            lock (_lock)
            {
                return _trustedPublishers.ContainsKey(thumbprint);
            }
        }

        public void Add(PublisherCertificateIdentity publisherIdentity)
        {
            ArgumentNullException.ThrowIfNull(publisherIdentity);

            string? thumbprint = NormalizeSha256Thumbprint(publisherIdentity.Sha256Thumbprint);
            if (thumbprint == null ||
                string.IsNullOrWhiteSpace(publisherIdentity.Subject) ||
                string.IsNullOrWhiteSpace(publisherIdentity.Issuer))
            {
                return;
            }

            var normalizedIdentity = publisherIdentity with { Sha256Thumbprint = thumbprint };

            lock (_lock)
            {
                if (_trustedPublishers.TryAdd(thumbprint, normalizedIdentity))
                {
                    Save();
                }
            }
        }

        public void Remove(PublisherWhitelistEntry entry)
        {
            ArgumentNullException.ThrowIfNull(entry);

            lock (_lock)
            {
                bool removed;
                if (entry.IsLegacy)
                {
                    removed = _legacyPublisherNames.Remove(entry.Subject);
                }
                else
                {
                    string? thumbprint = NormalizeSha256Thumbprint(entry.Sha256Thumbprint);
                    removed = thumbprint != null && _trustedPublishers.Remove(thumbprint);
                }

                if (removed)
                {
                    Save();
                }
            }
        }

        private static string? NormalizeSha256Thumbprint(string? thumbprint)
        {
            if (string.IsNullOrWhiteSpace(thumbprint))
            {
                return null;
            }

            string normalized = thumbprint
                .Replace(" ", string.Empty, StringComparison.Ordinal)
                .Replace(":", string.Empty, StringComparison.Ordinal)
                .ToUpperInvariant();

            if (normalized.Length != 64 || normalized.Any(character => !Uri.IsHexDigit(character)))
            {
                return null;
            }

            return normalized;
        }

        private void Save()
        {
            lock (_lock)
            {
                try
                {
                    var document = new PublisherWhitelistDocument
                    {
                        Version = CurrentDocumentVersion,
                        Publishers = _trustedPublishers.Values
                            .OrderBy(publisher => publisher.Sha256Thumbprint, StringComparer.OrdinalIgnoreCase)
                            .ToList(),
                        LegacyNames = _legacyPublisherNames
                            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                            .ToList()
                    };

                    string json = JsonSerializer.Serialize(
                        document,
                        WhitelistJsonContext.Default.PublisherWhitelistDocument);

                    string tempPath = _configPath + ".tmp";
                    File.WriteAllText(tempPath, json);
                    File.Move(tempPath, _configPath, overwrite: true);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[ERROR] Failed to save publisher whitelist: {ex.Message}");
                }
            }
        }
    }

    internal sealed class PublisherWhitelistDocument
    {
        public int Version { get; set; } = 2;
        public List<PublisherCertificateIdentity> Publishers { get; set; } = [];
        public List<string> LegacyNames { get; set; } = [];
    }

    [JsonSourceGenerationOptions(WriteIndented = true)]
    [JsonSerializable(typeof(HashSet<string>))]
    [JsonSerializable(typeof(PublisherWhitelistDocument))]
    internal partial class WhitelistJsonContext : JsonSerializerContext { }
}
