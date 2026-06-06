MRuby::Build.new do |conf|
  toolchain :gcc
  conf.enable_debug
  conf.gembox 'default'
  conf.gem '.' do |c|
    case ENV['REGEXP_LIB']
    when 'pcre'
      c.add_dependency 'mruby-regexp-pcre',
        :github => 'iij/mruby-regexp-pcre'
    when 'onig'
      c.add_dependency 'mruby-onig-regexp',
        :github => 'mattn/mruby-onig-regexp'
    when 'native'
      c.add_dependency 'mruby-regexp'
    end
  end
  conf.enable_test
end
