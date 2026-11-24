using System;
using System.IO;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class WildCardRuleServiceTests
{
    [Fact]
    public void Match_StarWildcard_MatchesFilenameAndSubpathCaseInsensitively()
    {
        using var service = CreateService();
        service.AddRule(new WildcardRule
        {
            FolderPath = @"C:\Program Files\App\*",
            ExeName = "*.exe",
            Action = "Allow Outbound"
        });

        Assert.NotNull(service.Match(@"c:\program files\app\Client.EXE"));
    }

    [Fact]
    public void Match_QuestionMarkWildcard_MatchesSingleCharacterOnly()
    {
        using var service = CreateService();
        service.AddRule(new WildcardRule
        {
            FolderPath = @"C:\Apps\*",
            ExeName = "tool?.exe",
            Action = "Allow Outbound"
        });

        Assert.NotNull(service.Match(@"C:\Apps\tool1.exe"));
        Assert.Null(service.Match(@"C:\Apps\tool12.exe"));
    }

    [Fact]
    public void Match_PathWithRegexMetacharacters_EscapesLiteralCharacters()
    {
        using var service = CreateService();
        service.AddRule(new WildcardRule
        {
            FolderPath = @"C:\Program Files (x86)\App+1\[v1]\*",
            ExeName = "tool.exe",
            Action = "Allow Outbound"
        });

        Assert.NotNull(service.Match(@"C:\Program Files (x86)\App+1\[v1]\tool.exe"));
        Assert.Null(service.Match(@"C:\Program Files x86\App11\v1\tool.exe"));
    }

    [Fact]
    public void Match_PathWithSpacesAndUnicode_MatchesAccurately()
    {
        using var service = CreateService();
        service.AddRule(new WildcardRule
        {
            FolderPath = @"C:\Ứng dụng\Công cụ\*",
            ExeName = "ứng dụng.exe",
            Action = "Allow Outbound"
        });

        Assert.NotNull(service.Match(@"c:\ứng dụng\công cụ\ỨNG DỤNG.EXE"));
    }

    [Fact]
    public void Match_NormalizedSlashes_HandlesMixedDirectorySeparators()
    {
        using var service = CreateService();
        service.AddRule(new WildcardRule
        {
            FolderPath = @"C:\Apps\Tools\*",
            ExeName = "*.exe",
            Action = "Allow Outbound"
        });

        Assert.NotNull(service.Match("C:/Apps/Tools/client.exe"));
    }

    [Fact]
    public void Match_NullOrWhitespace_ReturnsNullSafely()
    {
        using var service = CreateService();

        Assert.Null(service.Match(string.Empty));
        Assert.Null(service.Match("   "));
    }

    [Fact]
    public void AddRule_DuplicatePattern_DoesNotCreateDuplicateEntry()
    {
        using var service = CreateService();
        var rule = new WildcardRule
        {
            FolderPath = @"C:\Apps\*",
            ExeName = "*.exe",
            Action = "Allow Outbound"
        };

        service.AddRule(rule);
        service.AddRule(new WildcardRule
        {
            FolderPath = @"c:\apps\*",
            ExeName = "*.EXE",
            Action = "Block Outbound"
        });

        Assert.Single(service.GetRules());
    }

    [Fact]
    public void Match_NonMatchingPath_ReturnsNull()
    {
        using var service = CreateService();
        service.AddRule(new WildcardRule
        {
            FolderPath = @"C:\Apps\*",
            ExeName = "*.exe",
            Action = "Allow Outbound"
        });

        Assert.Null(service.Match(@"C:\Other\client.dll"));
    }

    [Fact]
    public void AddAndRemoveRule_RestoresEmptyRuleSet()
    {
        using var service = CreateService();
        var rule = new WildcardRule
        {
            FolderPath = @"C:\Apps\*",
            ExeName = "tool.exe",
            Action = "Allow Outbound"
        };

        service.AddRule(rule);
        Assert.Single(service.GetRules());

        service.RemoveRule(rule);
        Assert.Empty(service.GetRules());
    }

    private static WildcardRuleService CreateService()
    {
        string path = Path.Combine(Path.GetTempPath(), $"minimalfirewall-wildcard-{Guid.NewGuid():N}.json");
        return new WildcardRuleService(path);
    }
}
