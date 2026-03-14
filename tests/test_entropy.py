from src.entropy import shannon_entropy, is_high_entropy

class TestEntropy:
    def test_low_entropy_string(self):
        # "hello world" is predictable
        entropy = shannon_entropy("hello world")
        assert entropy < 3.5
        assert not is_high_entropy("hello world hello world", threshold=4.5)

    def test_high_entropy_string(self):
        # completely random base64 style secret
        random_secret = "AKIAIOSFODNN7EXAMPLEZXRU89SD"
        entropy = shannon_entropy(random_secret)
        assert entropy > 4.0
        # By default this should trigger if long enough
        assert is_high_entropy(random_secret, threshold=4.0)

    def test_short_string_ignored(self):
        # A short string even if random should not trigger the alert to avoid FP
        short_random = "aZ9$x"
        assert not is_high_entropy(short_random, threshold=2.0, min_length=16)

    def test_empty_string(self):
        assert shannon_entropy("") == 0.0
        assert not is_high_entropy("")

    def test_entropy_requires_mixed_classes(self):
        # A long natural sentence has high entropy but no numbers/special chars mixed
        natural_phrase = "Ceci est une longue phrase en francais tres normale sans aucun secret"
        # It should NOT be flagged as a secret
        assert not is_high_entropy(natural_phrase, threshold=4.0)
        
        # A mixed string of similar length SHOULD be flagged
        mixed_secret = "Ceci_est_un3_l0ngue_phr4se_4v3c_d3s_ch1ffr3s"
        assert is_high_entropy(mixed_secret, threshold=4.0)
