MRuby::Gem::Specification.new 'mruby-bcrypt' do |spec|
  spec.license  = 'MIT'
  spec.author   = 'Emanuele Vicentini'
  spec.summary  = 'OpenBSD-style Blowfish-based password hashing'
  spec.homepage = 'https://github.com/baldowl/mruby-bcrypt'

  spec.objs += Dir.glob("#{spec.dir}/src/crypt_blowfish/*.[cS]").
    map{|f| f.relative_path_from(dir).pathmap("#{build_dir}/%X.o")}

  spec.add_dependency 'mruby-onig-regexp',
    :github => 'mattn/mruby-onig-regexp',
    :checksum_hash => '0667cffa26db180ce3f6ed3b0341e9f30f1ae247'
  spec.add_dependency 'mruby-secure-compare',
    :github => 'Asmod4n/mruby-secure-compare',
    :checksum_hash => '433a73a483b550ad13e3a9af33707300c1c7822d'
  spec.add_dependency 'mruby-sysrandom',
    :github => 'Asmod4n/mruby-sysrandom',
    :checksum_hash => '4ba26c4ddf18091475c183026758ca167e73df93'

  spec.add_test_dependency 'mruby-time'
end
