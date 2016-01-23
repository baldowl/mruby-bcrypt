module BCrypt
  class Engine
    DEFAULT_COST = 10
    # Algorithm's lower limit
    MIN_COST     = 4
    # Implementation's upper limit
    MAX_COST     = 31
    RANDOM_BYTES = 16

    @cost = nil

    def self.cost
      @cost || DEFAULT_COST
    end

    def self.valid_cost? cost
      return false unless cost.respond_to?(:to_i)
      cost = cost.to_i
      cost == 0 || (MIN_COST..MAX_COST).include?(cost)
    end

    def self.cost=(cost)
      @cost = valid_cost?(cost) ? cost.to_i : DEFAULT_COST
    end

    def self.generate_salt(cost = self.cost)
      cost = valid_cost?(cost) ? cost.to_i : DEFAULT_COST
      __bc_salt '$2b$', cost, __bc_random_bytes(RANDOM_BYTES)
    end

    def self.calibrate upper_time_limit_in_ms
      (MIN_COST..MAX_COST).each do |current_cost|
        start_time = Time.now
        Password.create 'plain text password', :cost => current_cost
        elapsed_time = (Time.now - start_time) * 1000
        previous_cost = current_cost > MIN_COST ? current_cost - 1 : current_cost
        return previous_cost if elapsed_time > upper_time_limit_in_ms
      end
    end
  end
end
