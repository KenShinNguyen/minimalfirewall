using System;
using System.Linq;
using System.Net;
using MinimalFirewall.TypedObjects;
using Xunit;

namespace MinimalFirewall.Tests;

public sealed class TypedObjectRangeTests
{
    [Theory]
    [InlineData("0", 0, 0)]
    [InlineData("65535", 65535, 65535)]
    [InlineData("443", 443, 443)]
    [InlineData("100-200", 100, 200)]
    [InlineData("200-100", 100, 200)]
    public void PortRange_TryParse_ParsesAndNormalizesNumericRanges(
        string input,
        int expectedBegin,
        int expectedEnd)
    {
        var parsed = PortRange.TryParse(input, out var range);

        Assert.True(parsed);
        Assert.NotNull(range);
        Assert.Equal((ushort)expectedBegin, range.Begin);
        Assert.Equal((ushort)expectedEnd, range.End);
    }

    [Theory]
    [InlineData("RPC", "RPC")]
    [InlineData("rpc", "RPC")]
    [InlineData("RPC_EPMap", "RPC-EPMap")]
    [InlineData("rpc-epmap", "RPC-EPMap")]
    [InlineData("IPHTTPS", "IPHTTPS")]
    public void PortRange_TryParse_SupportsNamedLocalPorts(string input, string expected)
    {
        Assert.True(PortRange.TryParse(input, out var range));
        Assert.NotNull(range);
        Assert.Equal(expected, range.ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("-1")]
    [InlineData("65536")]
    [InlineData("1-")]
    [InlineData("-2")]
    [InlineData("1-2-3")]
    [InlineData("RPC-Unknown")]
    [InlineData("443/tcp")]
    public void PortRange_TryParse_RejectsInvalidInput(string? input)
    {
        Assert.False(PortRange.TryParse(input!, out var range));
        Assert.Null(range);
    }

    [Fact]
    public void PortRange_EqualityAndHashCode_UseNumericBoundaries()
    {
        var first = new PortRange(200, 100);
        var second = new PortRange(100, 200);

        Assert.Equal(second, first);
        Assert.Equal(second.GetHashCode(), first.GetHashCode());
        Assert.Equal("100-200", first.ToString());
    }

    [Fact]
    public void PortRange_NamedAndNumericValuesRemainDistinct()
    {
        var named = new PortRange(SpecificLocalPort.RPC);
        var numeric = new PortRange((ushort)135);

        Assert.NotEqual(named, numeric);
        Assert.Equal("RPC", named.ToString());
    }

    [Fact]
    public void IPAddressRange_TryParse_CidrMasksHostBits()
    {
        Assert.True(IPAddressRange.TryParse("192.168.1.42/24", out var range));

        Assert.NotNull(range);
        Assert.Equal(IPAddress.Parse("192.168.1.0"), range.Begin);
        Assert.Equal(IPAddress.Parse("192.168.1.255"), range.End);
        Assert.True(range.Contains(IPAddress.Parse("192.168.1.42")));
    }

    [Fact]
    public void IPAddressRange_TryParse_HandlesIpv4BoundaryPrefixes()
    {
        Assert.True(IPAddressRange.TryParse("192.0.2.10/0", out var allIpv4));
        Assert.NotNull(allIpv4);
        Assert.Equal(IPAddress.Parse("0.0.0.0"), allIpv4.Begin);
        Assert.Equal(IPAddress.Parse("255.255.255.255"), allIpv4.End);

        Assert.True(IPAddressRange.TryParse("192.0.2.10/32", out var singleIpv4));
        Assert.NotNull(singleIpv4);
        Assert.Equal(IPAddress.Parse("192.0.2.10"), singleIpv4.Begin);
        Assert.Equal(singleIpv4.Begin, singleIpv4.End);
    }

    [Fact]
    public void IPAddressRange_TryParse_HandlesIpv6Cidr()
    {
        Assert.True(IPAddressRange.TryParse("2001:db8:abcd:12::1234/64", out var range));

        Assert.NotNull(range);
        Assert.Equal(IPAddress.Parse("2001:db8:abcd:12::"), range.Begin);
        Assert.Equal(IPAddress.Parse("2001:db8:abcd:12:ffff:ffff:ffff:ffff"), range.End);
    }

    [Theory]
    [InlineData("192.0.2.1/-1")]
    [InlineData("192.0.2.1/33")]
    [InlineData("2001:db8::1/-1")]
    [InlineData("2001:db8::1/129")]
    public void IPAddressRange_TryParse_RejectsCidrPrefixOutsideAddressFamilyBounds(string input)
    {
        Assert.False(IPAddressRange.TryParse(input, out var range));
        Assert.Null(range);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("not-an-ip")]
    [InlineData("192.0.2.1/abc")]
    [InlineData("192.0.2.1/24/extra")]
    public void IPAddressRange_TryParse_RejectsMalformedInput(string? input)
    {
        Assert.False(IPAddressRange.TryParse(input!, out var range));
        Assert.Null(range);
    }

    [Theory]
    [InlineData("192.0.2.10-192.0.2.1")]
    [InlineData("192.0.2.1-2001:db8::1")]
    public void IPAddressRange_TryParse_RejectsReversedOrMixedFamilyRangesWithoutThrowing(
        string input)
    {
        var parsed = IPAddressRange.TryParse(input, out var range);

        Assert.False(parsed);
        Assert.Null(range);
    }

    [Fact]
    public void IPAddressRange_TryParse_ParsesInclusiveAddressRange()
    {
        Assert.True(IPAddressRange.TryParse("192.0.2.10-192.0.2.12", out var range));

        Assert.NotNull(range);
        Assert.Equal(IPAddress.Parse("192.0.2.10"), range.Begin);
        Assert.Equal(IPAddress.Parse("192.0.2.12"), range.End);
        Assert.Equal("192.0.2.10-192.0.2.12", range.ToString());
    }

    [Fact]
    public void IPAddressRange_Parse_ThrowsFormatExceptionForInvalidRange()
    {
        Assert.Throws<FormatException>(() =>
            IPAddressRange.Parse("192.0.2.10-192.0.2.1"));
    }

    [Fact]
    public void IPAddressRange_Constructor_RejectsNullEndpoints()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new IPAddressRange(null!, IPAddress.Parse("192.0.2.1")));
        Assert.Throws<ArgumentNullException>(() =>
            new IPAddressRange(IPAddress.Parse("192.0.2.1"), null!));
    }

    [Fact]
    public void IPAddressRange_Constructor_RejectsDifferentAddressFamilies()
    {
        Assert.Throws<ArgumentException>(() =>
            new IPAddressRange(
                IPAddress.Parse("192.0.2.1"),
                IPAddress.Parse("2001:db8::1")));
    }

    [Fact]
    public void IPAddressRange_Constructor_RejectsReversedEndpoints()
    {
        Assert.Throws<ArgumentException>(() =>
            new IPAddressRange(
                IPAddress.Parse("192.0.2.2"),
                IPAddress.Parse("192.0.2.1")));
    }

    [Fact]
    public void IPAddressRange_Contains_IsInclusiveAndRejectsOtherAddressFamilies()
    {
        var range = new IPAddressRange(
            IPAddress.Parse("192.0.2.10"),
            IPAddress.Parse("192.0.2.12"));

        Assert.True(range.Contains(IPAddress.Parse("192.0.2.10")));
        Assert.True(range.Contains(IPAddress.Parse("192.0.2.11")));
        Assert.True(range.Contains(IPAddress.Parse("192.0.2.12")));
        Assert.False(range.Contains(IPAddress.Parse("192.0.2.9")));
        Assert.False(range.Contains(IPAddress.Parse("192.0.2.13")));
        Assert.False(range.Contains(IPAddress.Parse("2001:db8::1")));
    }

    [Fact]
    public void IPAddressRange_Enumeration_IncludesBothEndpoints()
    {
        var range = new IPAddressRange(
            IPAddress.Parse("192.0.2.10"),
            IPAddress.Parse("192.0.2.12"));

        Assert.Equal(
            new[]
            {
                IPAddress.Parse("192.0.2.10"),
                IPAddress.Parse("192.0.2.11"),
                IPAddress.Parse("192.0.2.12")
            },
            range.ToArray());
    }

    [Fact]
    public void IPAddressRange_Enumeration_TerminatesAtMaximumIpv4Address()
    {
        var range = new IPAddressRange(
            IPAddress.Parse("255.255.255.254"),
            IPAddress.Parse("255.255.255.255"));

        var addresses = range.ToArray();

        Assert.Equal(2, addresses.Length);
        Assert.Equal(IPAddress.Parse("255.255.255.254"), addresses[0]);
        Assert.Equal(IPAddress.Parse("255.255.255.255"), addresses[1]);
    }

    [Fact]
    public void IPAddressRange_Enumeration_TerminatesAtMaximumIpv6Address()
    {
        var range = new IPAddressRange(
            IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"),
            IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));

        var addresses = range.ToArray();

        Assert.Equal(2, addresses.Length);
        Assert.Equal(IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"), addresses[0]);
        Assert.Equal(IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), addresses[1]);
    }

    [Fact]
    public void IPAddressRange_EqualityAndHashCode_UseBothEndpoints()
    {
        var first = new IPAddressRange(
            IPAddress.Parse("192.0.2.10"),
            IPAddress.Parse("192.0.2.20"));
        var second = IPAddressRange.Parse("192.0.2.10-192.0.2.20");

        Assert.Equal(second, first);
        Assert.Equal(second.GetHashCode(), first.GetHashCode());
    }

    [Fact]
    public void ProtocolTypes_ExposeExpectedPortAndIcmpCapabilities()
    {
        Assert.True(ProtocolTypes.TCP.SupportsPorts);
        Assert.True(ProtocolTypes.UDP.SupportsPorts);
        Assert.False(ProtocolTypes.ICMPv4.SupportsPorts);
        Assert.True(ProtocolTypes.ICMPv4.SupportsIcmp);
        Assert.True(ProtocolTypes.ICMPv6.SupportsIcmp);
        Assert.Equal(6, ProtocolTypes.TCP.Value);
        Assert.Equal(17, ProtocolTypes.UDP.Value);
        Assert.Equal("Any", ProtocolTypes.Any.ToString());
    }
}
