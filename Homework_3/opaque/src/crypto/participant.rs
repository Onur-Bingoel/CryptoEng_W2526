pub struct User {
    pub(crate) name: String,
}

impl User {
    pub fn new(name: String) -> Self {
        User {
            name,
        }
    }

    pub fn send_message(&self, title: String, target_name: String, silent: bool) {
        if silent { return; }
        let self_name = self.name.clone();
        println!("--- Sending {title} from {self_name} to {target_name} ---");
    }

}