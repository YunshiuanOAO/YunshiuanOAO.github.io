import type { UserConfig } from "../src/site.config";

const userConfig: UserConfig = {
  title: "Blog",
  description:
    "Some writeup or research in here",

  url: "https://yunshiuan.com",
  author: "yunshiuan",

  logo: "/logo.svg",
  avatar: "/avatar.png",

  navigation: [
    { title: "Writing", url: "/posts" },
    { title: "Archive", url: "/archive" },
    { title: "About", url: "/about" },
  ],

  footerLinks: [
    { title: "RSS", url: "/rss.xml" },
    { title: "Archive", url: "/archive" }

  ],

  social: [
    {
      title: "GitHub",
      url: "https://github.com/YunshiuanOAO",
      icon: "github",
    },
    {
      title: "X",
      url: "https://x.com/seanchou1101",
      icon: "x",
    },
    {
      title: "LinkedIn",
      url: "https://www.linkedin.com/in/yunshiuan-chou-914701313/",
      icon: "linkedin",
    },

  ],

  footerCredits: "Designed for reading. Built with Astro & Lipi",

  postsPerPage: 8,
  recentPosts: 6,
  relatedPosts: 4,

  showThemeToggle: true,
  showReadingTime: true,

  heroVariant: "studio"

  // annotation: "Writing between filter coffees and terminal windows.",
};

export default userConfig;
