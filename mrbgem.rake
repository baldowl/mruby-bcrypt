MRuby::Gem::Specification.new 'mruby-bcrypt' do |spec|
  spec.license  = 'MIT'
  spec.author   = 'Emanuele Vicentini'
  spec.summary  = 'OpenBSD-style Blowfish-based password hashing'
  spec.homepage = 'https://github.com/baldowl/mruby-bcrypt'

  spec.objs += Dir.glob("#{spec.dir}/src/crypt_blowfish/*.[cS]").
    map{|f| f.relative_path_from(dir).pathmap("#{build_dir}/%X.o")}

  spec.add_dependency 'mruby-regexp-pcre',
    :github => 'iij/mruby-regexp-pcre'
  spec.add_dependency 'mruby-secure-compare',
    :github => 'Asmod4n/mruby-secure-compare'
  spec.add_dependency 'mruby-sysrandom',
    :github => 'Asmod4n/mruby-sysrandom'

  spec.add_test_dependency 'mruby-time'
end
