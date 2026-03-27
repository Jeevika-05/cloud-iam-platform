const baseUrl = 'http://localhost:3001/api/v1';

async function testApi() {
  const credentials = {
    name: 'TestUser',
    email: `test${Date.now()}@test.com`,
    password: 'SecurePassword123!',
  };

  try {
    console.log('\n=== 1. Testing Registration ===');
    let res = await fetch(`${baseUrl}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials),
    });
    
    // Parse cookies from headers manually (fetch API in Node)
    const setCookie = res.headers.get('set-cookie');
    let data = await res.json();
    console.log('Status:', res.status);
    console.log('Response:', data.message || data.success);
    
    let token = data.data?.accessToken;
    let cookie = setCookie ? setCookie.split(';')[0] : '';

    console.log('\n=== 2. Testing Login ===');
    res = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: credentials.email, password: credentials.password }),
    });
    data = await res.json();
    console.log('Status:', res.status);
    console.log('Response:', data.message || data.success);
    token = data.data?.accessToken;
    cookie = res.headers.get('set-cookie') ? res.headers.get('set-cookie').split(';')[0] : cookie;

    console.log('\n=== 3. Testing Get Profile ===');
    res = await fetch(`${baseUrl}/auth/profile`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    data = await res.json();
    console.log('Status:', res.status);
    console.log('Profile Email:', data.data?.user?.email);

    console.log('\n=== 4. Testing Refresh Token ===');
    res = await fetch(`${baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'Cookie': cookie }
    });
    data = await res.json();
    console.log('Status:', res.status);
    console.log('Refreshed Token Received:', !!data.data?.accessToken);
    let newToken = data.data?.accessToken;

    console.log('\n=== 5. Testing Active Sessions ===');
    res = await fetch(`${baseUrl}/auth/sessions`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${newToken}` }
    });
    data = await res.json();
    console.log('Status:', res.status);
    console.log('Active Sessions Count:', data.data?.sessions?.length);

    console.log('\n=== 6. Testing Revoke All Sessions (Logout from all) ===');
    res = await fetch(`${baseUrl}/auth/sessions`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${newToken}` }
    });
    data = await res.json();
    console.log('Status:', res.status);
    console.log('Response:', data.message || data.success);

    console.log('\n=== API Testing Complete ✅ ===\n');

  } catch(err) {
    console.error('Test Failed:', err.message);
  }
}

testApi();
