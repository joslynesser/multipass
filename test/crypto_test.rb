# encoding: UTF-8

$LOAD_PATH << File.join(File.dirname(__FILE__), '..', 'lib')
require 'rubygems'
require 'test/unit'
require 'multipass'
require 'ezcrypto'

class MultiPass::CryptoTest < Test::Unit::TestCase

  def test_encryption_without_random_iv
    crypto = MultiPass::Crypto.new("site_key", "api_key")
    plain = "Very important data"
    encrypted = crypto.encrypt(plain)
    decrypted = crypto.decrypt(encrypted)
    assert_equal plain, decrypted
  end

  def test_encryption_with_random_iv
    crypto = MultiPass::Crypto.new("site_key", "api_key", random_iv: true)
    plain = "Very important data"
    encrypted = crypto.encrypt(plain)
    decrypted = crypto.decrypt(encrypted)
    assert_equal plain, decrypted
  end

  def test_same_output_as_ezcrypto_without_random_iv
    crypto = MultiPass::Crypto.new("site_key", "api_key")
    plain = "Very important data"
    encrypted = crypto.encrypt(plain)
    decrypted = EzCrypto::Key.with_password("site_key", "api_key").decrypt(encrypted)
    assert_equal plain, decrypted
  end
end