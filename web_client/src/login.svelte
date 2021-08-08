<script>

let username = "";
let password = "";

function login() {
    console.log(username, password);
}

</script>

<div class="container">
    <h2>Login</h2>
    <div>
        <p>Username</p>
        <input id="username" type="text" on:input="{e => username = e.target.value}">
    </div>
    <div>
        <p>Password</p>
        <input id="password" type="password" on:input="{e => password = e.target.value}">
    </div>
    <button on:click={login}>Submit</button>
</div>

<style>
.container {
    margin: 20px auto;
    width: 50%;
}

input {
    width: 100%;
}
</style>
