using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;

namespace MinimalFirewall.Tests.Architecture;

internal sealed record SourceDocument(string FileName, string Content);

internal static class CSharpSourceSanitizer
{
    public static string StripCommentsAndLiterals(string source)
    {
        ArgumentNullException.ThrowIfNull(source);

        var chars = source.ToCharArray();
        int index = 0;

        while (index < source.Length)
        {
            char current = source[index];
            char next = index + 1 < source.Length ? source[index + 1] : '\0';

            if (current == '/' && next == '/')
            {
                int end = source.IndexOfAny(['\r', '\n'], index + 2);
                MaskRange(chars, index, end < 0 ? source.Length : end);
                index = end < 0 ? source.Length : end;
                continue;
            }

            if (current == '/' && next == '*')
            {
                int close = source.IndexOf("*/", index + 2, StringComparison.Ordinal);
                int end = close < 0 ? source.Length : close + 2;
                MaskRange(chars, index, end);
                index = end;
                continue;
            }

            int literalPrefixEnd = index;
            while (literalPrefixEnd < source.Length &&
                source[literalPrefixEnd] is '$' or '@')
            {
                literalPrefixEnd++;
            }

            if (literalPrefixEnd < source.Length && source[literalPrefixEnd] == '"')
            {
                int quoteCount = 1;
                while (literalPrefixEnd + quoteCount < source.Length &&
                    source[literalPrefixEnd + quoteCount] == '"')
                {
                    quoteCount++;
                }

                bool verbatim = source.AsSpan(index, literalPrefixEnd - index).Contains('@');
                int literalQuoteCount = !verbatim && quoteCount >= 3 ? quoteCount : 1;
                int end = FindStringLiteralEnd(source, literalPrefixEnd, literalQuoteCount, verbatim);
                MaskRange(chars, index, end);
                index = end;
                continue;
            }

            if (current == '"')
            {
                int end = FindStringLiteralEnd(source, index, 1, verbatim: false);
                MaskRange(chars, index, end);
                index = end;
                continue;
            }

            if (current == '\'')
            {
                int end = FindCharacterLiteralEnd(source, index);
                MaskRange(chars, index, end);
                index = end;
                continue;
            }

            index++;
        }

        return new string(chars);
    }

    public static string StripMethodBody(string sanitizedSource, string methodName)
    {
        ArgumentNullException.ThrowIfNull(sanitizedSource);
        ArgumentException.ThrowIfNullOrWhiteSpace(methodName);

        var signaturePattern = new Regex(
            $@"\b{Regex.Escape(methodName)}\s*\([^)]*\)",
            RegexOptions.CultureInvariant);
        var chars = sanitizedSource.ToCharArray();

        foreach (Match match in signaturePattern.Matches(sanitizedSource))
        {
            int bodyStart = match.Index + match.Length;
            while (bodyStart < chars.Length && char.IsWhiteSpace(chars[bodyStart]))
            {
                bodyStart++;
            }

            // A call such as InitializeServices(); is not a method declaration.
            if (bodyStart >= chars.Length || chars[bodyStart] != '{')
            {
                continue;
            }

            int bodyEnd = FindMatchingBrace(sanitizedSource, bodyStart);
            if (bodyEnd >= 0)
            {
                MaskRange(chars, bodyStart + 1, bodyEnd);
            }
        }

        return new string(chars);
    }

    public static string StripLinesMatching(
        string sanitizedSource,
        IReadOnlyList<string> linePatterns)
    {
        ArgumentNullException.ThrowIfNull(sanitizedSource);
        ArgumentNullException.ThrowIfNull(linePatterns);

        var chars = sanitizedSource.ToCharArray();
        var patterns = linePatterns
            .Select(pattern => new Regex(pattern, RegexOptions.CultureInvariant))
            .ToArray();

        int lineStart = 0;
        while (lineStart < sanitizedSource.Length)
        {
            int newline = sanitizedSource.IndexOf('\n', lineStart);
            int lineEnd = newline < 0 ? sanitizedSource.Length : newline;
            string line = sanitizedSource.Substring(lineStart, lineEnd - lineStart);

            if (patterns.Any(pattern => pattern.IsMatch(line)))
            {
                MaskRange(chars, lineStart, lineEnd);
            }

            lineStart = newline < 0 ? sanitizedSource.Length : newline + 1;
        }

        return new string(chars);
    }

    private static int FindStringLiteralEnd(
        string source,
        int quoteStart,
        int quoteCount,
        bool verbatim)
    {
        int index = quoteStart + quoteCount;

        // C# raw string literals use three or more opening quote characters.
        if (quoteCount >= 3)
        {
            string delimiter = new('"', quoteCount);
            int close = source.IndexOf(delimiter, index, StringComparison.Ordinal);
            return close < 0 ? source.Length : close + quoteCount;
        }

        while (index < source.Length)
        {
            if (verbatim && source[index] == '"' &&
                index + 1 < source.Length && source[index + 1] == '"')
            {
                index += 2;
                continue;
            }

            if (!verbatim && source[index] == '\\')
            {
                index = Math.Min(index + 2, source.Length);
                continue;
            }

            if (source[index] == '"')
            {
                return index + 1;
            }

            index++;
        }

        return source.Length;
    }

    private static int FindCharacterLiteralEnd(string source, int quoteStart)
    {
        int index = quoteStart + 1;
        while (index < source.Length)
        {
            if (source[index] == '\\')
            {
                index = Math.Min(index + 2, source.Length);
                continue;
            }

            if (source[index] == '\'')
            {
                return index + 1;
            }

            index++;
        }

        return source.Length;
    }

    private static int FindMatchingBrace(string source, int openingBrace)
    {
        int depth = 0;

        for (int index = openingBrace; index < source.Length; index++)
        {
            if (source[index] == '{')
            {
                depth++;
            }
            else if (source[index] == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return index;
                }
            }
        }

        return -1;
    }

    private static void MaskRange(char[] chars, int start, int end)
    {
        for (int index = start; index < end; index++)
        {
            if (chars[index] is not '\r' and not '\n')
            {
                chars[index] = ' ';
            }
        }
    }
}

internal static class ArchitectureBoundaryEvaluator
{
    public static IReadOnlyList<string> FindForbiddenSourceTokens(
        IEnumerable<SourceDocument> documents,
        IReadOnlyList<string> forbiddenIdentifiers,
        IReadOnlySet<string> allowedFileNames,
        IReadOnlyDictionary<string, IReadOnlyList<string>>? scopedMethodExceptions = null,
        IReadOnlyDictionary<string, IReadOnlyList<string>>? scopedLineExceptions = null)
    {
        ArgumentNullException.ThrowIfNull(documents);
        ArgumentNullException.ThrowIfNull(forbiddenIdentifiers);
        ArgumentNullException.ThrowIfNull(allowedFileNames);

        var compiledPatterns = forbiddenIdentifiers
            .Select(identifier =>
            {
                bool isPrefixToken = identifier.EndsWith('_') ||
                    identifier.Equals("INetFw", StringComparison.Ordinal);
                string pattern = isPrefixToken
                    ? $@"\b{Regex.Escape(identifier)}"
                    : $@"\b{Regex.Escape(identifier)}\b";

                return (Identifier: identifier, Pattern: new Regex(pattern, RegexOptions.CultureInvariant));
            })
            .ToArray();

        var violations = new List<string>();

        foreach (var document in documents)
        {
            if (allowedFileNames.Contains(document.FileName))
            {
                continue;
            }

            string effectiveSource = CSharpSourceSanitizer.StripCommentsAndLiterals(document.Content);

            if (scopedMethodExceptions is not null &&
                scopedMethodExceptions.TryGetValue(document.FileName, out var exemptMethods))
            {
                foreach (string methodName in exemptMethods)
                {
                    effectiveSource = CSharpSourceSanitizer.StripMethodBody(effectiveSource, methodName);
                }
            }

            if (scopedLineExceptions is not null &&
                scopedLineExceptions.TryGetValue(document.FileName, out var exemptLines))
            {
                effectiveSource = CSharpSourceSanitizer.StripLinesMatching(effectiveSource, exemptLines);
            }

            var lines = effectiveSource.Split('\n');
            for (int lineIndex = 0; lineIndex < lines.Length; lineIndex++)
            {
                string line = lines[lineIndex];
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                foreach (var (identifier, pattern) in compiledPatterns)
                {
                    if (pattern.IsMatch(line))
                    {
                        violations.Add(
                            $"{document.FileName}:{lineIndex + 1} -> forbidden reference '{identifier}'");
                    }
                }
            }
        }

        return violations;
    }

    public static IReadOnlyList<string> FindForbiddenTypeReferences(
        IEnumerable<Type> targetTypes,
        Func<Type, bool> isForbiddenType,
        string ruleLabel,
        IReadOnlyDictionary<Type, IReadOnlySet<string>>? ignoredMembersByType = null)
    {
        ArgumentNullException.ThrowIfNull(targetTypes);
        ArgumentNullException.ThrowIfNull(isForbiddenType);
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleLabel);

        var violations = new List<string>();

        foreach (Type owner in targetTypes)
        {
            IReadOnlySet<string>? ignoredMembers = null;
            ignoredMembersByType?.TryGetValue(owner, out ignoredMembers);

            foreach (var (memberLabel, referencedType) in CollectMemberTypes(owner, ignoredMembers))
            {
                if (isForbiddenType(referencedType))
                {
                    violations.Add(
                        $"{owner.Name}.{memberLabel} -> [{ruleLabel}] '{referencedType.FullName ?? referencedType.Name}'");
                }
            }
        }

        return violations;
    }

    private static IEnumerable<(string MemberLabel, Type ReferencedType)> CollectMemberTypes(
        Type owner,
        IReadOnlySet<string>? ignoredMembers)
    {
        const BindingFlags flags =
            BindingFlags.Instance |
            BindingFlags.Static |
            BindingFlags.Public |
            BindingFlags.NonPublic |
            BindingFlags.DeclaredOnly;

        foreach (ConstructorInfo constructor in owner.GetConstructors(flags))
        {
            foreach (ParameterInfo parameter in constructor.GetParameters())
            {
                foreach (Type referencedType in UnwrapType(parameter.ParameterType))
                {
                    yield return ($"ctor({parameter.Name})", referencedType);
                }
            }
        }

        foreach (FieldInfo field in owner.GetFields(flags))
        {
            foreach (Type referencedType in UnwrapType(field.FieldType))
            {
                yield return ($"field:{field.Name}", referencedType);
            }
        }

        foreach (PropertyInfo property in owner.GetProperties(flags))
        {
            foreach (Type referencedType in UnwrapType(property.PropertyType))
            {
                yield return ($"prop:{property.Name}", referencedType);
            }
        }

        foreach (MethodInfo method in owner.GetMethods(flags))
        {
            if (method.IsSpecialName || ignoredMembers?.Contains(method.Name) == true)
            {
                continue;
            }

            foreach (Type referencedType in UnwrapType(method.ReturnType))
            {
                yield return ($"method:{method.Name}:return", referencedType);
            }

            foreach (ParameterInfo parameter in method.GetParameters())
            {
                foreach (Type referencedType in UnwrapType(parameter.ParameterType))
                {
                    yield return ($"method:{method.Name}({parameter.Name})", referencedType);
                }
            }
        }
    }

    private static IEnumerable<Type> UnwrapType(Type type)
    {
        if (type.IsByRef || type.IsArray || type.IsPointer)
        {
            Type? elementType = type.GetElementType();
            if (elementType is not null)
            {
                foreach (Type nestedType in UnwrapType(elementType))
                {
                    yield return nestedType;
                }
            }

            yield break;
        }

        yield return type;

        if (type.IsGenericType)
        {
            foreach (Type argument in type.GetGenericArguments())
            {
                foreach (Type nestedType in UnwrapType(argument))
                {
                    yield return nestedType;
                }
            }
        }
    }
}
