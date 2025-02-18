use balance::{recover_wallet_state, EXTENDED_PRIVATE_KEY, WALLET_NAME};

fn main() {
    let wallet_state = recover_wallet_state(EXTENDED_PRIVATE_KEY).unwrap();
    let balance = wallet_state.balance();

    println!("{} {:.8}", WALLET_NAME, balance);
}
