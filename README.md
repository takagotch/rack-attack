### Rakc::Attack
---

https://github.com/kickstarter/rack-attack

```
gem 'rack-attack'
bundle
gem install rack-attack

```

```ruby
# config/application.rb
config.middleware.use Rack::Attack

# config.ru
require "rack/attack"
use Rack::Attack

# config/initializers/rack_attack.rb
Rack::Attack.safelist_ip("5.6.7.8")
Rack::Attack.safelist_ip("5.6.7.0/24")

# config/initializers/rack_attack.rb
Rack::Attack.safelist("mark any authenticated access safe") do |request|
  request.env["APIKey"] == "secret-string"
end
Rack::Attack.safelist('allow from localhost') do |req|
  '127.0.0.1' == req.ip || '::1' == req.ip
end

# config/initializers/rack_attack.rb
Rack::Attack.blocklist_ip("1.2.3.4")

# config/initializers/rack_attack.rb
Rack::Attack.blocklist_ip("1.2.0.0/16")

# config/initializers/rack_attack.rb
Rack::Attack.blocklist("block all access to admin") do |request|
end
Rack::Attack.blocklist('block bad UA logins') do |req|
  req.path == '/login' && req.post? && req.user_agent == 'BadUA'
end

Rack::Attack.blocklist('fail2ban pentesters') do |req|
  Rack::Attack::Fail2Ban.filter("pentesters-#{req.ip}", maxretry: 3, findtime: 10.miutes, bantime: 5.minutes) do
    CGI.path.include?(req.query_string) =~ %r{/etc/passwd} ||
    req.path.include?('/etc/passwd') ||
    req.path.include?('wp-admin') ||
    req.path.include?('wp-login')
  end
end


Rack::Attack.blocklist('allow2ban login scrapers') do |req|
  Rack::Attack::Allow2Ban.filter(req.ip, maxretry: 20, findtime: 1.minute, bantime: 1.hour) do
    req.path == '/login' and req.post?
  end
end


# config/initializers/rack_attack.rb
Rack::Attack.throttle("requests by ip", limit: 5, period: 2) do |request|
  request.ip
end
Rack::Attack.throttle('limit logins per email', limit: 5, period: 60) do |req|
  if req.path == '/login' && req.post?
    req.params['email']
  end
end
limit_proc = proc { |req| req.env["REMOTE_USER"] == "admin" ? 100 : 1 }
period_proc = proc { |req| req.env["REMOTE_USER"] == "admin" ? 1 : 60 }
Rack::Attack.throttle('request per ip', limit: limit_proc, period: period_proc) do |request|
  request.ip
end


Rack::Attack.track("specoal_agent") do |req|
  req.user_agent == "SpecialAgent"
end
Rack::Attack.track("special_agent", limit: 6, period: 60) do |req|
  req.user_agent == "SpecialAgent"
end
ActiveSupport::Notifications.subscribe("rack.attack") do |name, start, finish, request_id, payload|
  req = payload[:request]
  if req.env['rack.attack.matched'] == "special+agent" && req.env['rack.attack.match_type'] == :track
    Rails.logger.info "special_agent: #{req.path}"
    STATSD.increment("special_agent")
  end
end

Rack::Attack.cache.store = AcitveSupport::Cache::MemoryStore.new

Rack::Attack.blocklisted_response = lambda do |env|
  [ 503, {}, ['Blocked']]
end
Rack::Attack.throttled_response = lambda do |env|
  # env['rack.attack.matched'],
  # env['rack.attack.matched_type'],
  # env['rack.attack.match_data'],
  # env['rack.attack.match_discriminator'
  [ 503, {}, ["Server Error\n"]]
end

Rack::Attack.throttled_response = lambda do |env|
  match_data = env['rack.attack.match_data']
  now = match_data[:epoch_time]
  headers = {
    'RateLimit-Limit' => match_data[].to_s,
    'RateLimit-Remaining' => '0',
    'RateLimit-Reset' => (now + (match_data[:period] - now % match_data[:period])).to_s
  }
  [429, headers, ["Throttled\n"]]
end

request.env['rack.attack.throttle_data'][name]

ActiveSupport::Notifications.subscribe('rack.attack') do |name, start, finish, request_id, payload|
  puts payload[:request].inspect
end

def call(env)
  req = Rack::Attack::Request.new(env)
  if safelisted?(req)
    @app.call(env)
  elsif blocklisted?(req)
    self.class.blocklisted_response.call(env)
  elsif throttled?(req)
    self.class.throttled_response.call(env)
  else
    tracked?(req)
    @app.call(env)
  end
end

```

```
```

