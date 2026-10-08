from src.validator import classify_indicator, is_routable_ip


def test_classify_ipv4():
    assert classify_indicator("8.8.8.8") == "ipv4"
    assert classify_indicator("192.168.1.1") == "ipv4"


def test_classify_hashes():
    assert classify_indicator("44d88612fea8a8f36de82e1278abb02f") == "hash_md5"
    assert classify_indicator("253b3f4625b55016f46646b5e1b979e273f760f3") == "hash_sha1"
    assert classify_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash_sha256"


def test_classify_invalid():
    assert classify_indicator("not-an-indicator") == "unknown"
    assert classify_indicator("999.999.999.999") == "unknown"


def test_routable_ip_filtering():
    assert is_routable_ip("1.1.1.1") is True
    assert is_routable_ip("192.168.0.5") is False
    assert is_routable_ip("10.0.0.1") is False
    assert is_routable_ip("127.0.0.1") is False
