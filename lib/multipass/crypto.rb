require 'openssl'
require 'digest/sha1'
require 'base64'

class MultiPass
  class Crypto

    def initialize(site_key, api_key, options = {})
      @key = generate_key(site_key, api_key)
      @random_iv = options[:random_iv]
    end

    def encrypt64(data)
      Base64.encode64(encrypt(data))
    end

    def decrypt64(data)
      decrypt(Base64.decode64(data))
    end

    def encrypt(data)
      cipher = OpenSSL::Cipher::Cipher.new("aes-128-cbc")
      cipher.encrypt
      cipher.key = @key

      if @random_iv
        cipher.random_iv + cipher.update(data) + cipher.final
      else
        cipher.update(data) + cipher.final
      end
    end

    def decrypt(data)
      decipher = OpenSSL::Cipher::Cipher.new("aes-128-cbc")
      decipher.decrypt
      decipher.key = @key

      if @random_iv
        decipher.iv = data.slice!(0,16)
      end

      decipher.update(data) + decipher.final
    end

    private

      def generate_key(password, salt)
        Digest::SHA1.digest(salt + password)[0...16]
      end

  end
end