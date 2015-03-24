# encoding: UTF-8

$LOAD_PATH << File.join(File.dirname(__FILE__), '..', 'lib')
require 'rubygems'
require 'test/unit'
require 'multipass'
#require 'active_support'

module MultiPassTestHelper
  def assert_multipass(expected, actual)
    assert_equal expected[:email], actual[:email]
    assert_equal expected[:expires].to_s, actual[:expires].to_s
  end
end

module MultiPassTests
  include MultiPassTestHelper

  def test_encodes_multipass
    expected = MultiPass.encode_64(@key.encrypt(@output.to_json), @mp.url_safe?)
    assert_equal expected, @mp.encode(@input)
  end

  def test_decodes_multipass
    encoded = @mp.encode(@input)
    assert_multipass @input, @mp.decode(encoded)
  end

  def test_decodes_multipass_with_class_method
    encoded = @mp.encode(@input)
    assert_multipass @input, MultiPass.decode('example', 'abc', encoded)
  end

  def test_decodes_unicode
    @input[:name] = "Bj\\u00f8rn"
    encoded = @mp.encode(@input)
    decoded = @mp.decode(encoded)
    assert_equal "Bjørn", decoded[:name]
  end

  def test_invalidates_bad_string
    assert_raises MultiPass::DecryptError do
      @mp.decode("abc")
    end
  end

  def test_invalidates_bad_json
    assert_raises MultiPass::JSONError do
      @mp.decode(@key.encrypt64("abc"))
    end
    assert_raises MultiPass::JSONError do
      @mp.decode(@key.encrypt64("{a"))
    end
  end

  def test_invalidates_old_expiration
    encrypted = @key.encrypt64(@input.merge(:expires => (Time.now - 1)).to_json)
    assert_raises MultiPass::ExpiredError do
      @mp.decode(encrypted)
    end
  end
end

class StandardMultiPassTest < Test::Unit::TestCase
  include MultiPassTests

  def setup
    @date   = Time.now + 1234
    @input  = {:expires => @date, :email => 'ricky@bobby.com'}
    @output = @input.merge(:expires => @input[:expires].to_s)
    @key    = MultiPass::Crypto.new('example', 'abc')
    @mp     = MultiPass.new('example', 'abc', :url_safe => false)
  end
end

class UrlSafeMultiPassTest < Test::Unit::TestCase
  include MultiPassTests

  def test_encodes_multipass_with_class_method
    expected = MultiPass.encode_64(@key.encrypt(@output.to_json), @mp.url_safe?)
    assert_equal expected, MultiPass.encode('example', 'abc', @input)
  end

  def setup
    @date   = Time.now + 1234
    @input  = {:expires => @date, :email => 'ricky@bobby.com'}
    @output = @input.merge(:expires => @input[:expires].to_s)
    @key    = MultiPass::Crypto.new('example', 'abc')
    @mp     = MultiPass.new('example', 'abc', :url_safe => true)
  end
end

class RandomIvMultiPassTest < Test::Unit::TestCase
  include MultiPassTestHelper

  def test_encodes_multipass
    expected = MultiPass.encode_64(@key.encrypt(@output.to_json), @mp.url_safe?)
    assert_not_equal expected, @mp.encode(@input)
  end

  def test_decodes_multipass
    encoded = @mp.encode(@input)
    assert_multipass @input, @mp.decode(encoded)
  end

  def setup
    @date   = Time.now + 1234
    @input  = {:expires => @date, :email => 'ricky@bobby.com'}
    @output = @input.merge(:expires => @input[:expires].to_s)
    @key    = MultiPass::Crypto.new('example', 'abc', :random_iv => true)
    @mp     = MultiPass.new('example', 'abc', :random_iv => true, :url_safe => false)
  end
end

class ErrorTest < Test::Unit::TestCase
  include MultiPassTestHelper

  def setup
    @key = MultiPass::Crypto.new('example', 'abc')
    @mp  = MultiPass.new('example', 'abc')
  end

  def test_decrypt_error_stores_data
    begin
      @mp.decode 'abc'
    rescue MultiPass::DecryptError => e
      assert_equal 'abc', e.data
    end
  end

  def test_json_error_stores_data
    begin
      data = @key.encrypt64("abc")
      @mp.decode data
    rescue MultiPass::JSONError => e
      assert_equal data, e.data
    end
  end

  def test_json_error_stores_json
    begin
      data = @key.encrypt64("{a")
      @mp.decode data
    rescue MultiPass::JSONError => e
      assert_equal "{a", e.json
    end
  end

  def test_expiration_error_stores_data
    begin
      json = {:expires => Time.now - 5, :email => 'ricky@bobby.com'}.to_json
      data = @key.encrypt64(json)
      @mp.decode data
    rescue MultiPass::ExpiredError => e
      assert_equal data, e.data
    end
  end

  def test_expiration_error_stores_json
    begin
      json = {:expires => Time.now - 5, :email => 'ricky@bobby.com'}.to_json
      data = @key.encrypt64(json)
      @mp.decode data
    rescue MultiPass::ExpiredError => e
      assert_equal json, e.json
    end
  end

  def test_expiration_error_stores_options
    begin
      opt  = {:expires => Time.now - 5, :email => 'ricky@bobby.com'}
      json = opt.to_json
      data = @key.encrypt64(json)
      @mp.decode data
    rescue MultiPass::ExpiredError => e
      assert_multipass opt, e.options
    end
  end
end
