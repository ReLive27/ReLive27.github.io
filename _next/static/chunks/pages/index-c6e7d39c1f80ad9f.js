(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[405],{8581:function(t,e,n){(window.__NEXT_P=window.__NEXT_P||[]).push(["/",function(){return n(4369)}])},7726:function(t,e,n){"use strict";n.d(e,{w:function(){return m}});var r=n(4051),a=n.n(r),i=n(7320),o=n(1720),c=n(1576),l=n.n(c);function s(t,e,n,r,a,i,o){try{var c=t[i](o),l=c.value}catch(s){return void n(s)}c.done?e(l):Promise.resolve(l).then(r,a)}var u=function(t){var e=t.title,n=void 0===e?"Subscribe to the newsletter":e,r=(0,o.useRef)(null),c=(0,o.useState)(!1),u=c[0],m=c[1],d=(0,o.useState)(""),p=d[0],f=d[1],h=(0,o.useState)(!1),g=h[0],y=h[1],x=function(){var t,e=(t=a().mark((function t(e){var n;return a().wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return e.preventDefault(),t.next=3,fetch("/api/".concat(l().newsletter.provider),{body:JSON.stringify({email:r.current.value}),headers:{"Content-Type":"application/json"},method:"POST"});case 3:return n=t.sent,t.next=6,n.json();case 6:if(!t.sent.error){t.next=11;break}return m(!0),f("Your e-mail address is invalid or you are already subscribed!"),t.abrupt("return");case 11:r.current.value="",m(!1),y(!0),f("Successfully! \ud83c\udf89 You are now subscribed.");case 15:case"end":return t.stop()}}),t)})),function(){var e=this,n=arguments;return new Promise((function(r,a){var i=t.apply(e,n);function o(t){s(i,r,a,o,c,"next",t)}function c(t){s(i,r,a,o,c,"throw",t)}o(void 0)}))});return function(t){return e.apply(this,arguments)}}();return(0,i.BX)("div",{children:[(0,i.tZ)("div",{className:"pb-1 text-lg font-semibold text-gray-800 dark:text-gray-100",children:n}),(0,i.BX)("form",{className:"flex flex-col sm:flex-row",onSubmit:x,children:[(0,i.BX)("div",{children:[(0,i.tZ)("label",{className:"sr-only",htmlFor:"email-input",children:"Email address"}),(0,i.tZ)("input",{autoComplete:"email",className:"w-72 rounded-md px-4 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-primary-600 dark:bg-black",id:"email-input",name:"email",placeholder:g?"You're subscribed !  \ud83c\udf89":"Enter your email",ref:r,required:!0,type:"email",disabled:g})]}),(0,i.tZ)("div",{className:"mt-2 flex w-full rounded-md shadow-sm sm:mt-0 sm:ml-3",children:(0,i.tZ)("button",{className:"w-full rounded-md bg-primary-500 py-2 px-4 font-medium text-white sm:py-0 ".concat(g?"cursor-default":"hover:bg-primary-700 dark:hover:bg-primary-400"," focus:outline-none focus:ring-2 focus:ring-primary-600 focus:ring-offset-2 dark:ring-offset-black"),type:"submit",disabled:g,children:g?"Thank you!":"Sign up"})})]}),u&&(0,i.tZ)("div",{className:"w-72 pt-2 text-sm text-red-500 dark:text-red-400 sm:w-96",children:p})]})},m=function(t){var e=t.title;return(0,i.tZ)("div",{className:"flex items-center justify-center",children:(0,i.tZ)("div",{className:"bg-gray-100 p-6 dark:bg-gray-800 sm:px-14 sm:py-8",children:(0,i.tZ)(u,{title:e})})})}},9831:function(t,e,n){"use strict";n.d(e,{TQ:function(){return s},$t:function(){return u},Uy:function(){return m}});var r=n(7320),a=n(9008),i=n(1163),o=n(1576),c=n.n(o),l=function(t){var e=t.title,n=t.description,o=t.ogType,l=t.ogImage,s=t.twImage,u=t.canonicalUrl,m=(0,i.useRouter)();return(0,r.BX)(a.default,{children:[(0,r.tZ)("title",{children:e}),(0,r.tZ)("meta",{name:"robots",content:"follow, index"}),(0,r.tZ)("meta",{name:"description",content:n}),(0,r.tZ)("meta",{property:"og:url",content:"".concat(c().siteUrl).concat(m.asPath)}),(0,r.tZ)("meta",{property:"og:type",content:o}),(0,r.tZ)("meta",{property:"og:site_name",content:c().title}),(0,r.tZ)("meta",{property:"og:description",content:n}),(0,r.tZ)("meta",{property:"og:title",content:e}),"Array"===l.constructor.name?l.map((function(t){var e=t.url;return(0,r.tZ)("meta",{property:"og:image",content:e},e)})):(0,r.tZ)("meta",{property:"og:image",content:l},l),(0,r.tZ)("meta",{name:"twitter:card",content:"summary_large_image"}),(0,r.tZ)("meta",{name:"twitter:site",content:c().twitter}),(0,r.tZ)("meta",{name:"twitter:title",content:e}),(0,r.tZ)("meta",{name:"twitter:description",content:n}),(0,r.tZ)("meta",{name:"twitter:image",content:s}),(0,r.tZ)("link",{rel:"canonical",href:u||"".concat(c().siteUrl).concat(m.asPath)})]})},s=function(t){var e=t.title,n=t.description,a=c().siteUrl+c().socialBanner,i=c().siteUrl+c().socialBanner;return(0,r.tZ)(l,{title:e,description:n,ogType:"website",ogImage:a,twImage:i})},u=function(t){var e=t.title,n=t.description,o=c().siteUrl+c().socialBanner,s=c().siteUrl+c().socialBanner,u=(0,i.useRouter)();return(0,r.BX)(r.HY,{children:[(0,r.tZ)(l,{title:e,description:n,ogType:"website",ogImage:o,twImage:s}),(0,r.tZ)(a.default,{children:(0,r.tZ)("link",{rel:"alternate",type:"application/rss+xml",title:"".concat(n," - RSS feed"),href:"".concat(c().siteUrl).concat(u.asPath,"/feed.xml")})})]})},m=function(t){var e=t.authorDetails,n=t.title,o=t.summary,s=t.date,u=t.lastmod,m=t.url,d=t.images,p=void 0===d?[]:d,f=t.canonicalUrl,h=((0,i.useRouter)(),new Date(s).toISOString()),g=new Date(u||s).toISOString(),y=(0===p.length?[c().socialBanner]:"string"===typeof p?[p]:p).map((function(t){return{"@type":"ImageObject",url:t.includes("http")?t:c().siteUrl+t}})),x={"@context":"https://schema.org","@type":"Article",mainEntityOfPage:{"@type":"WebPage","@id":m},headline:n,image:y,datePublished:h,dateModified:g,author:e?e.map((function(t){return{"@type":"Person",name:t.name}})):{"@type":"Person",name:c().author},publisher:{"@type":"Organization",name:c().author,logo:{"@type":"ImageObject",url:"".concat(c().siteUrl).concat(c().siteLogo)}},description:o},Z=y[0].url;return(0,r.BX)(r.HY,{children:[(0,r.tZ)(l,{title:n,description:o,ogType:"article",ogImage:y,twImage:Z,canonicalUrl:f}),(0,r.BX)(a.default,{children:[s&&(0,r.tZ)("meta",{property:"article:published_time",content:h}),u&&(0,r.tZ)("meta",{property:"article:modified_time",content:g}),(0,r.tZ)("script",{type:"application/ld+json",dangerouslySetInnerHTML:{__html:JSON.stringify(x,null,2)}})]})]})}},9019:function(t,e,n){"use strict";var r=n(7320),a=n(1664),i=n(4871);e.Z=function(t){var e=t.text;return(0,r.tZ)(a.default,{href:"/tags/".concat((0,i.Z)(e)),children:(0,r.tZ)("a",{className:"mr-3 text-sm font-medium uppercase text-primary-500 hover:text-primary-600 dark:hover:text-primary-400",children:e.split(" ").join("-")})})}},6232:function(t,e,n){"use strict";var r=n(1576),a=n.n(r);e.Z=function(t){return new Date(t).toLocaleDateString(a().locale,{year:"numeric",month:"long",day:"numeric"})}},4871:function(t,e,n){"use strict";var r=n(9671);e.Z=function(t){return(0,r.slug)(t)}},4369:function(t,e,n){"use strict";n.r(e),n.d(e,{__N_SSG:function(){return s},default:function(){return u}});var r=n(7320),a=n(7233),i=n(9831),o=(n(9019),n(1576)),c=n.n(o),l=(n(6232),n(2811)),s=(n(7726),!0);function u(t){t.posts;return(0,r.BX)(r.HY,{children:[(0,r.tZ)(i.TQ,{title:c().title,description:c().description}),(0,r.BX)("div",{className:"fade-in banner flex flex-1 flex-col justify-center px-6 py-10 dark:text-white lg:px-10",style:{marginTop:"100px"},children:[(0,r.BX)("h1",{className:"text-3xl font-bold dark:text-white lg:text-5xl",children:["Hi, I am ",c().author]}),(0,r.tZ)("p",{className:"my-2 text-lg lg:my-4 lg:text-2xl",children:"Intermediate Software Engineer"}),(0,r.BX)("p",{className:"font-light lg:text-xl",children:["Read more",(0,r.tZ)(a.Z,{className:"ml-2 mr-2 font-normal text-black",href:"/about",children:(0,r.tZ)(l.c,{show:!0,type:"highlight",animationDelay:250,animationDuration:2e3,color:"#F5E1FF",children:"about me"})}),"or",(0,r.tZ)(a.Z,{className:"ml-2 font-normal text-black",href:"/contact",children:(0,r.tZ)(l.c,{show:!0,type:"highlight",animationDelay:250,animationDuration:2e3,color:"#CAF0F8",children:"contact me"})})]})]})]})}}},function(t){t.O(0,[774,888,179],(function(){return e=8581,t(t.s=e);var e}));var e=t.O();_N_E=e}]);