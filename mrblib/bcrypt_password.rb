module BCrypt
  class Password
    attr_reader :version, :cost, :salt, :checksum

    def initialize raw_hash
      if self.class.valid_hash? raw_hash
        @raw_hash = raw_hash
        @version, @cost, @salt, @checksum = split_hash raw_hash
      else
        raise ArgumentError, 'invalid hash'
      end
    end

    def self.valid_hash? raw_hash
      !!(raw_hash =~ /^\$[0-9a-z]{2}\$[0-9]{2}\$[A-Za-z0-9\.\/]{53}$/)
    end

    def self.create secret, options = {}
      cost = options[:cost] || BCrypt::Engine.cost
      Password.new(BCrypt::Engine.hash_secret(secret.to_s,
        BCrypt::Engine.generate_salt(cost)))
    end

    # We cannot derive from String and add our own instance variables, and so
    # here's the conversion to String.
    def to_s
      @raw_hash
    end

    def ==(secret)
      BCrypt::Engine.hash_secret(secret, @salt) == @raw_hash
    end

    alias_method :is_password?, :==

    # NO-OP declaration; be kind and leave the following code alone :)
    private

    def split_hash raw_hash
      _, version, cost, blob = raw_hash.split '$'
      [version.to_s, cost.to_i, raw_hash[0, 29].to_s, blob[-31, 31].to_s]
    end
  end
end
