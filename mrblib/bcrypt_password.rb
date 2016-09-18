module BCrypt
  # A simple class which simplify password management.
  #
  #    # hash a user's password
  #    @password = BCrypt::Password.create("clever password")
  #    @password #=> "$2b$10$sY1GqryNhvSZCML11tjf.eVRJ31CcBCc.5LXUP/BoGgN/HZ4gRjk6"
  #
  #    # create a password object from a valid hash stored somewhere
  #    @password = BCrypt::Password.new(@stored_hash)
  #
  #    # compare password
  #    @password == "clever password" #=> true
  #    @password == "a wild guess"    #=> false
  class Password
    # The algorithm's version used to create this Blowfish hash.
    attr_reader :version
    # The cost factor used to create this hash.
    attr_reader :cost
    # The salt part of this Blowfish hash (includes version and cost).
    attr_reader :salt
    # The hash part of this Blowfish hash.
    attr_reader :checksum

    ##
    # call-seq:
    #    BCrypt::Password.new(string)    -> obj
    #
    # Initializes a BCrypt::Password object with a valid Blowfish hash. An
    # +ArgumentError+ exception is raised if the hash is invalid.
    def initialize raw_hash
      if self.class.valid_hash? raw_hash
        @raw_hash = raw_hash
        @version, @cost, @salt, @checksum = split_hash raw_hash
      else
        raise ArgumentError, 'invalid hash'
      end
    end

    ##
    # call-seq:
    #    BCrypt::Password.valid_hash?(string)    -> true or false
    #
    # Returns true if +raw_hash+ is a valid Blowfish hash.
    def self.valid_hash? raw_hash
      !!(raw_hash =~ /^\$[0-9a-z]{2}\$[0-9]{2}\$[A-Za-z0-9\.\/]{53}$/)
    end

    ##
    # call-seq:
    #    BCrypt::Password.create(string)                  -> obj
    #    BCrypt::Password.create(string, :cost => int)    -> obj
    #
    # Hashes +secret+ and returns a BCrypt::Password instance.
    #
    # The optional <tt>:cost</tt> determines how computational expensive the
    # hash calculation is: higher cost results in harder to guess passwords if
    # your stored hashes are stolen.
    #
    # The cost factor is logarithmic, so a cost of 15 is about twice as much
    # work as 14.
    #
    # BCrypt::Engine.cost is used if called without <tt>:cost</tt>.
    def self.create secret, options = {}
      cost = options[:cost] || BCrypt::Engine.cost
      Password.new(BCrypt::Engine.hash_secret(secret.to_s,
        BCrypt::Engine.generate_salt(cost)))
    end

    ##
    # call-seq:
    #    bcrypt_hash_obj.to_s    -> string
    #
    # We cannot derive from String and add our own instance variables, and so
    # here's the conversion to String.
    def to_s
      @raw_hash
    end

    ##
    # call-seq:
    #    bcrypt_hash_obj == "a password"    -> true or false
    #
    # Compares the hash against a potential, plain text, secret/password.
    # Returns true if +secret+ is the original secret/password (i.e., it can
    # be used to recreate the hash).
    def ==(secret)
      new_hash = BCrypt::Engine.hash_secret(secret, @salt)
      return false unless self.class.valid_hash?(new_hash)
      new_hash_bytes = new_hash.bytes
      result = 0
      @raw_hash.bytes.each {|byte| result |= byte ^ new_hash_bytes.shift}
      result == 0
    end

    alias_method :is_password?, :==

    # NO-OP declaration; be kind and leave the following code alone :)
    private

    ##
    # call-seq:
    #    BCrypt::Password.split_hash(string)    -> [version, cost, salt, hash]
    #
    # Splits +raw_hash+ into its basic components (algorithm's version, cost
    # factor, salt and hash).
    def split_hash raw_hash
      _, version, cost, blob = raw_hash.split '$'
      [version.to_s, cost.to_i, raw_hash[0, 29].to_s, blob[-31, 31].to_s]
    end
  end
end
