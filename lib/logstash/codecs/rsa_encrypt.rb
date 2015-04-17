# encoding: utf-8
require "logstash/codecs/base"
require "logstash/namespace"
require "logstash/json"

class LogStash::Codecs::RsaEncrypt < LogStash::Codecs::Base
  config_name "rsa_encrypt"

  # The location of the public key file.
  config :public_key_file, :validate => :path, :required => true

  public
  def initialize(params={})
    super(params)
    require "openssl"
    require "base64"
    @public_key = OpenSSL::PKey::RSA.new(File.read(public_key_file))
  end

  public
  def encode(event)
 
    # Create cipher with a random session key.
    cipher = OpenSSL::Cipher::Cipher.new('aes-128-cbc')
    cipher.encrypt
    cipher.key = session_key = cipher.random_key
    cipher.iv = session_iv = cipher.random_iv

    # Encrypt the data with the cipher.
    encrypted_data = cipher.update(event.to_json)
    encrypted_data << cipher.final

    # Encrypt session key with the public key.
    encrypted_key =  @public_key.public_encrypt(session_key)
    encrypted_iv = @public_key.public_encrypt(session_iv)

    # Base64 encode for transmission (might make this optional in the future).
    base64_encrypted_data = Base64.encode64(encrypted_data)
    base64_encrypted_key = Base64.encode64(encrypted_key)
    base64_encrypted_iv = Base64.encode64(encrypted_iv)

    # Package up the encrypted data and session keys.
    data = {}
    data["encrypted_data"] = base64_encrypted_data
    data["encrypted_key"] = base64_encrypted_key
    data["encrypted_iv"] = base64_encrypted_iv

    # Convert the payload to json and pass it on.
    data_json = LogStash::Json.dump(data)
    @on_event.call(event, data_json)

  end # def encode

end # class LogStash::Codecs::RsaEncrypt
