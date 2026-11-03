source "https://rubygems.org"

gemspec

group :development, :test do
  gem "rake", "~> 13.0"
  gem "rspec", "~> 3.13"
  gem "webmock", "~> 3.23"
  gem "bigdecimal"
  # Optional at RUNTIME (the gemspec declares no dependency on it) — present
  # here only so the wrap Faraday-transport specs can exercise a real Faraday
  # stack. wrap.faraday_connection lazily requires it and raises a clear error
  # when a consumer has not installed it.
  gem "faraday", "~> 2.0"
end
