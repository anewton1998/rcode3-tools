use askama::Template;

pub struct NavItem<'a> {
    pub label: &'a str,
    pub url: &'a str,
}

impl<'a> NavItem<'a> {
    pub fn new(label: &'a str, url: &'a str) -> Self {
        Self { label, url }
    }
}

#[derive(Template, Default)]
#[template(path = "link_nav.html")]
pub struct LinkNav<'a> {
    pub items: Vec<NavItem<'a>>,
}

impl<'a> LinkNav<'a> {
    pub fn item(mut self, label: &'a str, url: &'a str) -> Self {
        self.items.push(NavItem::new(label, url));
        self
    }
}
