package core

import (
	"reflect"
	"testing"
)

func TestProductionGems(t *testing.T) {
	gemfile := `source "https://rubygems.org"
gem "rails", "~> 8.0.0"
gem 'bcrypt' # passwords
gem "simplecov", require: false, group: :test
gem "pry-rails", group: :development
gem "pg", groups: [:default, :production]
gem("puma")

group :development, :test do
  gem "rspec-rails"
  platforms :mri do
    gem "byebug"
  end
  gem "capybara"
end

group :production do
  gem "lograge"
end

platforms :jruby do
  gem "jdbc-sqlite3"
end
gem "sidekiq", :require => false
# gem "commented"
`
	want := []string{"rails", "bcrypt", "pg", "puma", "lograge", "jdbc-sqlite3"}
	if got := productionGems(gemfile); !reflect.DeepEqual(got, want) {
		t.Errorf("productionGems = %v, want %v", got, want)
	}
}
