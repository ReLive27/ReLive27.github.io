(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[888],{425:function(e,t,n){"use strict";n.d(t,{f:function(){return s},F:function(){return i}});var r=n(1720),a=n(9008),o=(0,r.createContext)({setTheme:function(e){},themes:[]}),i=function(){return(0,r.useContext)(o)},c=["light","dark"],l="(prefers-color-scheme: dark)",s=function(e){var t=e.forcedTheme,n=e.disableTransitionOnChange,a=void 0!==n&&n,i=e.enableSystem,s=void 0===i||i,m=e.enableColorScheme,p=void 0===m||m,v=e.storageKey,g=void 0===v?"theme":v,y=e.themes,w=void 0===y?["light","dark"]:y,b=e.defaultTheme,x=void 0===b?s?"system":"light":b,O=e.attribute,_=void 0===O?"data-theme":O,j=e.value,E=e.children,k=(0,r.useState)((function(){return f(g,x)})),Z=k[0],z=k[1],T=(0,r.useState)((function(){return f(g)})),C=T[0],M=T[1],L=j?Object.values(j):w,N=(0,r.useCallback)((function(e){var n=h(e);M(n),"system"!==Z||t||A(n,!1)}),[Z,t]),S=(0,r.useRef)(N);S.current=N;var A=(0,r.useCallback)((function(e,t,n){void 0===t&&(t=!0),void 0===n&&(n=!0);var r=(null==j?void 0:j[e])||e,o=a&&n?d():null;if(t)try{localStorage.setItem(g,e)}catch(e){}if("system"===e&&s){var i=h();r=(null==j?void 0:j[i])||i}if(n){var c,l=document.documentElement;"class"===_?((c=l.classList).remove.apply(c,L),l.classList.add(r)):l.setAttribute(_,r),null==o||o()}}),[]);(0,r.useEffect)((function(){var e=function(){return S.current.apply(S,[].slice.call(arguments))},t=window.matchMedia(l);return t.addListener(e),e(t),function(){return t.removeListener(e)}}),[]);var I=(0,r.useCallback)((function(e){t?A(e,!0,!1):A(e),z(e)}),[t]);return(0,r.useEffect)((function(){var e=function(e){e.key===g&&I(e.newValue)};return window.addEventListener("storage",e),function(){return window.removeEventListener("storage",e)}}),[I]),(0,r.useEffect)((function(){if(p){var e=t&&c.includes(t)?t:Z&&c.includes(Z)?Z:"system"===Z&&C||null;document.documentElement.style.setProperty("color-scheme",e)}}),[p,Z,C,t]),r.default.createElement(o.Provider,{value:{theme:Z,setTheme:I,forcedTheme:t,resolvedTheme:"system"===Z?C:Z,themes:s?[].concat(w,["system"]):w,systemTheme:s?C:void 0}},r.default.createElement(u,{forcedTheme:t,storageKey:g,attribute:_,value:j,enableSystem:s,defaultTheme:x,attrs:L}),E)},u=(0,r.memo)((function(e){var t=e.forcedTheme,n=e.storageKey,o=e.attribute,i=e.enableSystem,c=e.defaultTheme,s=e.value,u="class"===o?"var d=document.documentElement.classList;d.remove("+e.attrs.map((function(e){return"'"+e+"'"})).join(",")+");":"var d=document.documentElement;",f=function(e,t){e=(null==s?void 0:s[e])||e;var n=t?e:"'"+e+"'";return"class"===o?"d.add("+n+")":"d.setAttribute('"+o+"', "+n+")"},d="system"===c;return r.default.createElement(a.default,null,r.default.createElement("script",t?{key:"next-themes-script",dangerouslySetInnerHTML:{__html:"!function(){"+u+f(t)+"}()"}}:i?{key:"next-themes-script",dangerouslySetInnerHTML:{__html:"!function(){try {"+u+"var e=localStorage.getItem('"+n+"');"+(d?"":f(c)+";")+'if("system"===e||(!e&&'+d+')){var t="'+l+'",m=window.matchMedia(t);m.media!==t||m.matches?'+f("dark")+":"+f("light")+"}else if(e) "+(s?"var x="+JSON.stringify(s)+";":"")+f(s?"x[e]":"e",!0)+"}catch(e){}}()"}}:{key:"next-themes-script",dangerouslySetInnerHTML:{__html:"!function(){try{"+u+'var e=localStorage.getItem("'+n+'");if(e){'+(s?"var x="+JSON.stringify(s)+";":"")+f(s?"x[e]":"e",!0)+"}else{"+f(c)+";}}catch(t){}}();"}}))}),(function(e,t){return e.forcedTheme===t.forcedTheme})),f=function(e,t){if("undefined"!=typeof window){var n;try{n=localStorage.getItem(e)||void 0}catch(e){}return n||t}},d=function(){var e=document.createElement("style");return e.appendChild(document.createTextNode("*{-webkit-transition:none!important;-moz-transition:none!important;-o-transition:none!important;-ms-transition:none!important;transition:none!important}")),document.head.appendChild(e),function(){window.getComputedStyle(document.body),setTimeout((function(){document.head.removeChild(e)}),1)}},h=function(e){return e||(e=window.matchMedia(l)),e.matches?"dark":"light"}},3454:function(e,t,n){"use strict";var r,a;e.exports=(null===(r=n.g.process)||void 0===r?void 0:r.env)&&"object"===typeof(null===(a=n.g.process)||void 0===a?void 0:a.env)?n.g.process:n(7663)},1780:function(e,t,n){(window.__NEXT_P=window.__NEXT_P||[]).push(["/_app",function(){return n(4442)}])},7233:function(e,t,n){"use strict";var r=n(7320),a=n(1664);function o(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{},r=Object.keys(n);"function"===typeof Object.getOwnPropertySymbols&&(r=r.concat(Object.getOwnPropertySymbols(n).filter((function(e){return Object.getOwnPropertyDescriptor(n,e).enumerable})))),r.forEach((function(t){o(e,t,n[t])}))}return e}function c(e,t){if(null==e)return{};var n,r,a=function(e,t){if(null==e)return{};var n,r,a={},o=Object.keys(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||(a[n]=e[n]);return a}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(a[n]=e[n])}return a}t.Z=function(e){var t=e.href,n=c(e,["href"]),o=t&&t.startsWith("/"),l=t&&t.startsWith("#");return o?(0,r.tZ)(a.default,{href:t,children:(0,r.tZ)("a",i({},n))}):l?(0,r.tZ)("a",i({href:t},n)):(0,r.tZ)("a",i({target:"_blank",rel:"noopener noreferrer",href:t},n))}},890:function(e,t,n){"use strict";n.d(t,{Z:function(){return a}});var r=n(7320);function a(e){var t=e.children;return(0,r.tZ)("div",{className:"mx-auto max-w-3xl px-4 sm:px-6 xl:max-w-5xl xl:px-0",children:t})}},4744:function(e,t,n){"use strict";n.d(t,{Z:function(){return N}});var r,a,o=n(7320),i=n(1720);function c(){return c=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},c.apply(this,arguments)}var l;function s(){return s=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},s.apply(this,arguments)}var u;function f(){return f=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},f.apply(this,arguments)}var d;function h(){return h=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},h.apply(this,arguments)}var m;function p(){return p=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},p.apply(this,arguments)}var v;function g(){return g=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},g.apply(this,arguments)}var y,w;function b(){return b=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},b.apply(this,arguments)}var x,O;function _(){return _=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},_.apply(this,arguments)}var j,E;function k(){return k=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},k.apply(this,arguments)}var Z;function z(){return z=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},z.apply(this,arguments)}var T,C;function M(){return M=Object.assign?Object.assign.bind():function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},M.apply(this,arguments)}var L={mail:function(e){return i.createElement("svg",c({xmlns:"http://www.w3.org/2000/svg",viewBox:"0 0 20 20",role:"img"},e),r||(r=i.createElement("path",{d:"M2.003 5.884 10 9.882l7.997-3.998A2 2 0 0 0 16 4H4a2 2 0 0 0-1.997 1.884z"})),a||(a=i.createElement("path",{d:"m18 8.118-8 4-8-4V14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8.118z"})))},github:function(e){return i.createElement("svg",s({viewBox:"0 0 24 24",xmlns:"http://www.w3.org/2000/svg",role:"img"},e),l||(l=i.createElement("path",{d:"M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"})))},juejin:function(e){return i.createElement("svg",b({className:"juejin_svg__icon",viewBox:"0 0 1024 1024",xmlns:"http://www.w3.org/2000/svg",role:"img"},e),y||(y=i.createElement("path",{d:"M465.189 161.792c-22.967 18.14-44.325 35.109-47.397 37.742l-5.851 4.68 10.971 8.632c5.998 4.827 11.85 9.508 13.02 10.532 1.17 1.024 17.993 14.336 37.156 29.696l34.962 27.795 5.267-3.95c2.925-2.194 23.259-18.432 45.348-35.986 21.943-17.555 41.253-32.768 42.716-33.646 1.609-1.024 2.779-2.194 2.779-2.78 0-.438-9.655-8.63-21.504-17.846-11.995-9.363-22.674-17.847-23.845-18.871-15.945-13.02-49.737-39.059-50.76-39.059-.586.147-19.896 14.922-42.862 33.061zm233.325 180.37C507.465 493.275 508.928 492.105 505.417 489.911c-3.072-1.902-11.556-8.485-64.073-50.03-9.07-7.168-18.578-14.775-21.358-16.823-2.78-2.194-8.777-6.875-13.312-10.532-4.68-3.657-10.679-8.339-13.312-10.533-13.165-10.24-71.095-56.027-102.107-80.457-5.852-4.681-11.41-8.485-12.142-8.485-.731 0-10.971 7.754-22.674 17.116-11.703 9.508-22.674 18.286-24.284 19.456-1.755 1.17-5.12 3.95-7.46 6.144-2.34 2.34-4.828 4.096-5.413 4.096-3.072 0-.731 3.072 6.437 8.777 4.096 3.218 8.777 6.875 10.094 8.046 1.316 1.024 10.24 8.045 19.748 15.506s23.26 18.286 30.428 23.99c19.31 15.215 31.89 25.308 127.853 101.084 47.836 37.742 88.796 69.779 90.844 71.095 3.657 2.487 3.95 2.487 7.46-.292a1041.42 1041.42 0 0 0 16.092-12.727c6.875-5.413 14.775-11.703 17.554-13.897 30.135-23.699 80.018-63.05 81.774-64.512 1.17-1.024 12.434-9.802 24.868-19.603s37.888-29.696 56.32-44.324c18.579-14.629 46.227-36.425 61.733-48.567 15.506-12.142 27.794-22.528 27.502-23.26-.878-1.17-57.637-47.104-59.978-48.274-.731-.439-18.578 12.727-39.497 29.257z"})),w||(w=i.createElement("path",{d:"M57.93 489.326c-15.215 12.288-28.527 23.405-29.697 24.576-2.34 2.194-5.412-.44 80.018 66.852 33.207 26.185 32.622 25.747 57.637 45.495 10.386 8.192 36.279 28.672 57.783 45.495 38.18 30.135 44.91 35.401 52.663 41.545 2.048 1.756 22.967 18.14 46.372 36.572 23.26 18.432 74.167 58.514 112.933 89.088 38.912 30.573 71.095 55.734 71.826 56.027.732.293 7.46-4.389 14.921-10.386 21.797-16.97 90.259-70.949 101.523-79.872 5.705-4.535 12.873-10.24 15.945-12.58 3.072-2.488 6.436-5.12 7.314-5.852.878-.878 11.85-9.509 24.283-19.31 20.773-16.091 59.1-46.226 64.366-50.615 1.17-1.024 5.12-4.096 8.777-6.875 3.657-2.78 7.9-6.29 9.509-7.607 1.609-1.317 14.775-11.703 29.257-23.113 29.11-22.82 42.277-33.207 88.503-69.632 17.262-13.605 32.475-25.454 33.646-26.478 2.486-2.048 31.451-24.869 44.617-35.255 4.827-3.657 9.07-7.168 9.508-7.607.44-.585 5.998-4.827 12.435-9.8 6.436-4.828 13.165-10.24 15.067-11.85l3.365-2.926-9.948-7.753c-5.412-4.388-10.24-8.192-10.679-8.63-1.17-1.317-22.381-18.433-30.135-24.284-3.95-3.072-7.314-5.998-7.606-6.73-1.317-3.071-6.73.147-29.258 17.994-13.458 10.532-25.746 20.187-27.355 21.504-1.61 1.463-10.533 8.338-19.749 15.652-9.216 7.168-17.115 13.459-17.554 13.898-.439.438-6.583 5.412-13.897 10.971-7.168 5.559-15.214 11.703-17.7 13.75-4.974 4.097-5.413 4.39-20.334 16.239-5.56 4.388-11.264 8.777-12.435 9.8-1.17 1.025-20.333 16.092-42.422 33.354-22.09 17.408-41.546 32.768-43.155 34.084-1.609 1.463-14.482 11.557-28.525 22.528s-40.814 32.037-59.539 46.812c-18.578 14.775-42.276 33.353-52.516 41.399s-23.26 18.285-28.965 22.82l-10.386 8.339-4.389-3.072c-2.34-1.756-4.68-3.511-5.12-3.95-.439-.439-4.973-4.096-10.24-8.046-11.849-9.216-14.482-11.264-16.676-13.166-.878-.877-4.243-3.51-7.46-5.851-3.22-2.487-6.145-4.681-6.584-5.12-.439-.439-6.875-5.705-14.482-11.703-7.607-5.851-14.921-11.556-16.091-12.58-1.317-1.17-17.116-13.605-35.255-27.795-17.993-14.19-35.109-27.648-38.035-29.842-5.705-4.681-33.499-26.624-125.074-98.743-34.523-27.209-72.704-57.344-84.846-66.852-49.737-39.498-55.15-43.594-56.905-43.447-.877 0-14.043 10.24-29.257 22.528z"})))},csdn:function(e){return i.createElement("svg",_({xmlns:"http://www.w3.org/2000/svg",width:24,height:24,role:"img"},e),x||(x=i.createElement("path",{d:"M13.36 13.974c.138.03.32.059.678.059 1.435 0 2.447-.779 2.548-1.874.148-1.583-.75-2.137-2.262-2.127-.196 0-.468 0-.612.029l-.352 3.913z",opacity:.3})),O||(O=i.createElement("path",{d:"M6.217 13.408c.447.18 1.379.359 2.132.359.812 0 1.264-.247 1.3-.632.033-.35-.299-.398-1.216-.637-1.267-.342-2.075-.871-1.996-1.717.092-.982 1.286-1.724 3.118-1.724.893 0 1.759.069 2.208.231l-.154 1.238c-.291-.112-1.406-.266-2.16-.266-.765 0-1.16.265-1.188.555-.034.367.363.385 1.356.676 1.345.376 1.933.905 1.856 1.725-.091.964-1.165 1.784-3.31 1.784-.893 0-1.663-.179-2.087-.359l.141-1.233zM18.821 9.366c4.884-1.017 5.305.811 5.154 2.428l-.284 2.992h-1.55l.259-2.729c.056-.601.405-1.776-1.281-1.732-.584.016-.873.104-.873.104s-.051.726-.112 1.263l-.294 3.095h-1.52l.302-3.05.199-2.371zM12.653 9.224c.349-.042.884-.084 1.621-.084 1.23 0 2.225.236 2.841.734.553.464.921 1.214.819 2.302-.094 1.012-.57 1.721-1.264 2.159-.635.413-1.434.59-2.637.59-.709 0-1.385-.042-1.9-.126l.52-5.575zm1.016 4.466a2.6 2.6 0 0 0 .582.051c1.231 0 2.098-.668 2.185-1.607.127-1.358-.643-1.832-1.94-1.824-.168 0-.401 0-.525.025l-.302 3.355zM5.335 14.813c-.292.111-.896.187-1.74.187-2.427 0-3.737-1.254-3.583-2.913C.198 10.112 2.139 9 4.264 9c.823 0 1.308.073 1.762.195l-.146 1.331c-.302-.112-1.01-.215-1.583-.215-1.25 0-2.312.41-2.434 1.707-.109 1.16.637 1.714 2.044 1.714.49 0 1.212-.077 1.545-.189l-.117 1.27z"})))},facebook:function(e){return i.createElement("svg",f({xmlns:"http://www.w3.org/2000/svg",viewBox:"0 0 24 24",role:"img"},e),u||(u=i.createElement("path",{d:"M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"})))},youtube:function(e){return i.createElement("svg",h({xmlns:"http://www.w3.org/2000/svg",viewBox:"0 0 24 24",role:"img"},e),d||(d=i.createElement("path",{d:"M23.499 6.203a3.008 3.008 0 0 0-2.089-2.089c-1.87-.501-9.4-.501-9.4-.501s-7.509-.01-9.399.501a3.008 3.008 0 0 0-2.088 2.09A31.258 31.26 0 0 0 0 12.01a31.258 31.26 0 0 0 .523 5.785 3.008 3.008 0 0 0 2.088 2.089c1.869.502 9.4.502 9.4.502s7.508 0 9.399-.502a3.008 3.008 0 0 0 2.089-2.09 31.258 31.26 0 0 0 .5-5.784 31.258 31.26 0 0 0-.5-5.808zm-13.891 9.4V8.407l6.266 3.604z"})))},linkedin:function(e){return i.createElement("svg",p({viewBox:"0 0 24 24",xmlns:"http://www.w3.org/2000/svg",role:"img"},e),m||(m=i.createElement("path",{d:"M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 0 1-2.063-2.065 2.064 2.064 0 1 1 2.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"})))},twitter:function(e){return i.createElement("svg",g({xmlns:"http://www.w3.org/2000/svg",viewBox:"0 0 24 24",role:"img"},e),v||(v=i.createElement("path",{d:"M23.953 4.57a10 10 0 0 1-2.825.775 4.958 4.958 0 0 0 2.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 0 0-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 0 0-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 0 1-2.228-.616v.06a4.923 4.923 0 0 0 3.946 4.827 4.996 4.996 0 0 1-2.212.085 4.936 4.936 0 0 0 4.604 3.417 9.867 9.867 0 0 1-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 0 0 7.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0 0 24 4.59z"})))},book:function(e){return i.createElement("svg",k({className:"book_svg__icon",viewBox:"0 0 1024 1024",xmlns:"http://www.w3.org/2000/svg",width:24,height:24,role:"img"},e),j||(j=i.createElement("path",{d:"M819.2 695.9H690.3c-78.6 0-171.9 31-171.9 31v52.9h300.8v-83.9zm-601.6 0h128.9c78.6 0 171.9 31 171.9 31v52.9H217.6v-83.9z",fill:"#00E7DD"})),E||(E=i.createElement("path",{d:"M820.3 259.7h-75.2v-60.2h-15c-2.3 0-4.3.6-6.3 1.5-2.8-.9-5.7-1.5-8.8-1.5h-60.2c-59.4 0-120.3 15-120.3 15-5.5 0-10.6 1.6-15 4.2-4.4-2.6-9.5-4.2-15-4.2 0 0-60.9-15-120.3-15H324c-3.1 0-6 .6-8.8 1.5-1.9-.9-4-1.5-6.3-1.5h-15v60.2h-75.2c-8.3 0-15 6.7-15 15v496.4c0 8.3 6.7 15 15 15h122.2c71.4 0 155.9 11.7 174.7 14.5 1.3.3 2.6.6 3.9.6 1.4 0 2.7-.2 3.9-.6 18.8-2.7 103.3-14.5 174.7-14.5h122.2c8.3 0 15-6.7 15-15V274.7c0-8.3-6.7-15-15-15zm-586.6 30.1h60.2v376h-60.2v-376zm270.7 481.3s-62.8-15-137.3-15H233.6v-60.2h60.2V726h15c2.3 0 4.3-.6 6.3-1.5 2.8.9 5.7 1.5 8.8 1.5h60.2c60.2 0 120.3 15 120.3 15v30.1zm0-75.2c0 8.3-6.7 15-15 15 0 0-52.6-15-105.3-15H339c-8.3 0-15-6.7-15-15V244.7c0-8.3 6.7-15 15-15h45.1c50.4 0 105.3 15 105.3 15 8.3 0 15 6.7 15 15v436.2zm30.1-436.2c0-8.3 6.7-15 15-15 0 0 54.9-15 105.3-15H700c8.3 0 15 6.7 15 15v436.2c0 8.3-6.7 15-15 15h-45.1c-52.6 0-105.3 15-105.3 15-8.3 0-15-6.7-15-15V259.7zm270.8 496.4H701.9c-74.4 0-167.3 15-167.3 15V741s60.2-15 120.3-15h60.2c3.1 0 6-.6 8.8-1.5 1.9.9 4 1.5 6.3 1.5h15v-30.1h60.2v60.2zm0-90.3h-60.2v-376h60.2v376z",fill:"#008CFF"})))},chemistry:function(e){return i.createElement("svg",z({className:"chemistry_svg__icon",viewBox:"0 0 1024 1024",xmlns:"http://www.w3.org/2000/svg",width:24,height:24,role:"img"},e),Z||(Z=i.createElement("path",{d:"M682.667 275.2C812.8 339.2 896 471.467 896 618.667v29.866c-17.067 196.267-181.333 354.134-384 354.134-211.2 0-384-172.8-384-384 0-147.2 83.2-279.467 213.333-343.467V106.667H320c-23.467 0-42.667-19.2-42.667-42.667s19.2-42.667 42.667-42.667h384c23.467 0 42.667 19.2 42.667 42.667s-19.2 42.667-42.667 42.667h-21.333V275.2zM755.2 578.133c17.067 6.4 32 12.8 53.333 17.067C800 482.133 729.6 384 622.933 341.333c-17.066-6.4-25.6-21.333-25.6-40.533V106.667H426.667v196.266c0 17.067-10.667 32-25.6 40.534-93.867 38.4-160 119.466-179.2 215.466C256 563.2 281.6 573.867 302.933 582.4c25.6 10.667 49.067 19.2 98.134 19.2s72.533-8.533 98.133-19.2c29.867-12.8 64-25.6 130.133-25.6 61.867-4.267 96 10.667 125.867 21.333zM512 917.333c142.933 0 262.4-102.4 292.267-236.8-34.134-4.266-59.734-14.933-81.067-23.466-25.6-10.667-49.067-19.2-98.133-19.2s-70.4 8.533-98.134 19.2c-29.866 12.8-64 25.6-130.133 25.6-66.133 0-100.267-12.8-130.133-25.6-17.067-6.4-32-12.8-53.334-17.067C226.133 795.733 356.267 917.333 512 917.333z",fill:"#2F3CF4"})))},educate:function(e){return i.createElement("svg",M({className:"educate_svg__icon",viewBox:"0 0 1024 1024",xmlns:"http://www.w3.org/2000/svg",width:24,height:24,role:"img"},e),T||(T=i.createElement("path",{d:"M511.97 673.68a60.92 60.92 0 0 1-31.81-8.95L92.23 427.75C74.7 417.13 64.09 398.62 64 378.24c-.08-20.38 10.42-39.06 28.06-49.96L480.13 91.37c19.65-12 44.06-11.97 63.71-.03L931.78 328.2c17.81 10.98 28.31 29.67 28.23 50.04-.08 20.32-10.64 38.81-28.23 49.51L543.9 664.7c-9.86 5.99-20.89 8.98-31.93 8.98zm-334.9-295.7L512 582.56l334.9-204.61L512 173.5 177.07 377.98zm-39.82-24.33.2.11c-.09-.05-.15-.08-.2-.11zm749.5 0c-.03 0-.06.03-.06.03s.04-.03.06-.03z",fill:"#7373FF"})),C||(C=i.createElement("path",{d:"M512.08 941.62c-99.75 0-191.2-33.19-250.87-91.06a43.32 43.32 0 0 1-13.18-31.13V498.56c0-15.69 8.47-30.15 22.16-37.82a43.23 43.23 0 0 1 43.81.82l198 121 198.2-121.15c13.41-8.16 30.17-8.5 43.81-.82a43.354 43.354 0 0 1 22.16 37.82v321.01c0 11.77-4.77 23-13.24 31.19-59.9 57.85-151.32 91.01-250.85 91.01zM334.74 799.87c43.58 34.69 108.39 55.04 177.34 55.04 68.81 0 133.62-20.35 177.37-55.1V575.73L543.9 664.7c-19.67 11.94-44.06 12-63.73.03l-145.42-88.85v223.99zm581.9-89.44c-23.94 0-43.35-19.42-43.35-43.35V378.04c0-23.94 19.42-43.35 43.35-43.35 23.94 0 43.35 19.42 43.35 43.35v289.03c.01 23.94-19.41 43.36-43.35 43.36z",fill:"#7373FF"})))}},N=function(e){var t=e.kind,n=e.href,r=e.size,a=void 0===r?8:r;if(!n||"mail"===t&&!/^mailto:\w+([.-]?\w+)@\w+([.-]?\w+)(.\w{2,3})+$/.test(n))return null;var i=L[t];return(0,o.BX)("a",{className:"text-sm text-gray-500 transition hover:text-gray-600",target:"_blank",rel:"noopener noreferrer",href:n,children:[(0,o.tZ)("span",{className:"sr-only",children:t}),(0,o.tZ)(i,{className:"fill-current text-gray-700 hover:text-blue-500 dark:text-gray-200 dark:hover:text-blue-400 h-".concat(a," w-").concat(a)})]})}},1576:function(e,t,n){"use strict";var r=n(3454),a={title:"ReLive27 Blog",author:"ReLive27",headerTitle:"ReLive27",description:"ReLive27's personal blog and website",language:"zh-cn",theme:"system",siteUrl:"",siteRepo:"https://github.com/ReLive27/relive27.com",siteLogo:"/static/images/logo.png",image:"/static/images/avatar.png",socialBanner:"/static/images/banner.png",email:"re_live27@163.com",github:"https://github.com/ReLive27",juejin:"https://juejin.cn/user/4051073081555869",csdn:"https://blog.csdn.net/new_ord?spm=1000.2115.3001.5343",twitter:"https://twitter.com/Twitter",facebook:"https://facebook.com",youtube:"https://youtube.com",linkedin:"https://www.linkedin.com",locale:"zh-cn",analytics:{plausibleDataDomain:"",simpleAnalytics:!1,umamiWebsiteId:"",googleAnalyticsId:"",posthogAnalyticsId:""},newsletter:{provider:"buttondown"},comment:{provider:"giscus",giscusConfig:{repo:"ReLive27/ReLive27.github.io",repositoryId:"R_kgDOHTAM5Q",category:"Announcements",categoryId:"DIC_kwDOHTAM5c4CR7sj",mapping:"pathname",reactions:"1",metadata:"0",theme:"light",inputPosition:"bottom",lang:"en",darkTheme:"transparent_dark",themeURL:""},utterancesConfig:{repo:r.env.NEXT_PUBLIC_UTTERANCES_REPO,issueTerm:"",label:"",theme:"",darkTheme:""},disqusConfig:{shortname:r.env.NEXT_PUBLIC_DISQUS_SHORTNAME}}};e.exports=a},1551:function(e,t,n){"use strict";function r(e,t){(null==t||t>e.length)&&(t=e.length);for(var n=0,r=new Array(t);n<t;n++)r[n]=e[n];return r}function a(e,t){return function(e){if(Array.isArray(e))return e}(e)||function(e,t){var n=null==e?null:"undefined"!==typeof Symbol&&e[Symbol.iterator]||e["@@iterator"];if(null!=n){var r,a,o=[],i=!0,c=!1;try{for(n=n.call(e);!(i=(r=n.next()).done)&&(o.push(r.value),!t||o.length!==t);i=!0);}catch(l){c=!0,a=l}finally{try{i||null==n.return||n.return()}finally{if(c)throw a}}return o}}(e,t)||function(e,t){if(!e)return;if("string"===typeof e)return r(e,t);var n=Object.prototype.toString.call(e).slice(8,-1);"Object"===n&&e.constructor&&(n=e.constructor.name);if("Map"===n||"Set"===n)return Array.from(n);if("Arguments"===n||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n))return r(e,t)}(e,t)||function(){throw new TypeError("Invalid attempt to destructure non-iterable instance.\\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}t.default=void 0;var o,i=(o=n(1720))&&o.__esModule?o:{default:o},c=n(1003),l=n(880),s=n(9246);var u={};function f(e,t,n,r){if(e&&c.isLocalURL(t)){e.prefetch(t,n,r).catch((function(e){0}));var a=r&&"undefined"!==typeof r.locale?r.locale:e&&e.locale;u[t+"%"+n+(a?"%"+a:"")]=!0}}var d=function(e){var t,n=!1!==e.prefetch,r=l.useRouter(),o=i.default.useMemo((function(){var t=a(c.resolveHref(r,e.href,!0),2),n=t[0],o=t[1];return{href:n,as:e.as?c.resolveHref(r,e.as):o||n}}),[r,e.href,e.as]),d=o.href,h=o.as,m=e.children,p=e.replace,v=e.shallow,g=e.scroll,y=e.locale;"string"===typeof m&&(m=i.default.createElement("a",null,m));var w=(t=i.default.Children.only(m))&&"object"===typeof t&&t.ref,b=a(s.useIntersection({rootMargin:"200px"}),2),x=b[0],O=b[1],_=i.default.useCallback((function(e){x(e),w&&("function"===typeof w?w(e):"object"===typeof w&&(w.current=e))}),[w,x]);i.default.useEffect((function(){var e=O&&n&&c.isLocalURL(d),t="undefined"!==typeof y?y:r&&r.locale,a=u[d+"%"+h+(t?"%"+t:"")];e&&!a&&f(r,d,h,{locale:t})}),[h,d,O,y,n,r]);var j={ref:_,onClick:function(e){t.props&&"function"===typeof t.props.onClick&&t.props.onClick(e),e.defaultPrevented||function(e,t,n,r,a,o,i,l){("A"!==e.currentTarget.nodeName.toUpperCase()||!function(e){var t=e.currentTarget.target;return t&&"_self"!==t||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey||e.nativeEvent&&2===e.nativeEvent.which}(e)&&c.isLocalURL(n))&&(e.preventDefault(),t[a?"replace":"push"](n,r,{shallow:o,locale:l,scroll:i}))}(e,r,d,h,p,v,g,y)},onMouseEnter:function(e){t.props&&"function"===typeof t.props.onMouseEnter&&t.props.onMouseEnter(e),c.isLocalURL(d)&&f(r,d,h,{priority:!0})}};if(e.passHref||"a"===t.type&&!("href"in t.props)){var E="undefined"!==typeof y?y:r&&r.locale,k=r&&r.isLocaleDomain&&c.getDomainLocale(h,E,r&&r.locales,r&&r.domainLocales);j.href=k||c.addBasePath(c.addLocale(h,E,r&&r.defaultLocale))}return i.default.cloneElement(t,j)};t.default=d},9246:function(e,t,n){"use strict";function r(e,t){(null==t||t>e.length)&&(t=e.length);for(var n=0,r=new Array(t);n<t;n++)r[n]=e[n];return r}function a(e,t){return function(e){if(Array.isArray(e))return e}(e)||function(e,t){var n=null==e?null:"undefined"!==typeof Symbol&&e[Symbol.iterator]||e["@@iterator"];if(null!=n){var r,a,o=[],i=!0,c=!1;try{for(n=n.call(e);!(i=(r=n.next()).done)&&(o.push(r.value),!t||o.length!==t);i=!0);}catch(l){c=!0,a=l}finally{try{i||null==n.return||n.return()}finally{if(c)throw a}}return o}}(e,t)||function(e,t){if(!e)return;if("string"===typeof e)return r(e,t);var n=Object.prototype.toString.call(e).slice(8,-1);"Object"===n&&e.constructor&&(n=e.constructor.name);if("Map"===n||"Set"===n)return Array.from(n);if("Arguments"===n||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n))return r(e,t)}(e,t)||function(){throw new TypeError("Invalid attempt to destructure non-iterable instance.\\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}Object.defineProperty(t,"__esModule",{value:!0}),t.useIntersection=function(e){var t=e.rootRef,n=e.rootMargin,r=e.disabled||!c,u=o.useRef(),f=a(o.useState(!1),2),d=f[0],h=f[1],m=a(o.useState(t?t.current:null),2),p=m[0],v=m[1],g=o.useCallback((function(e){u.current&&(u.current(),u.current=void 0),r||d||e&&e.tagName&&(u.current=function(e,t,n){var r=function(e){var t,n={root:e.root||null,margin:e.rootMargin||""},r=s.find((function(e){return e.root===n.root&&e.margin===n.margin}));r?t=l.get(r):(t=l.get(n),s.push(n));if(t)return t;var a=new Map,o=new IntersectionObserver((function(e){e.forEach((function(e){var t=a.get(e.target),n=e.isIntersecting||e.intersectionRatio>0;t&&n&&t(n)}))}),e);return l.set(n,t={id:n,observer:o,elements:a}),t}(n),a=r.id,o=r.observer,i=r.elements;return i.set(e,t),o.observe(e),function(){if(i.delete(e),o.unobserve(e),0===i.size){o.disconnect(),l.delete(a);var t=s.findIndex((function(e){return e.root===a.root&&e.margin===a.margin}));t>-1&&s.splice(t,1)}}}(e,(function(e){return e&&h(e)}),{root:p,rootMargin:n}))}),[r,p,n,d]);return o.useEffect((function(){if(!c&&!d){var e=i.requestIdleCallback((function(){return h(!0)}));return function(){return i.cancelIdleCallback(e)}}}),[d]),o.useEffect((function(){t&&v(t.current)}),[t]),[g,d]};var o=n(1720),i=n(4686),c="undefined"!==typeof IntersectionObserver;var l=new Map,s=[]},4442:function(e,t,n){"use strict";n.r(t),n.d(t,{default:function(){return Z}});var r=n(7320),a=(n(2604),n(7661),n(3941),n(8102),n(425)),o=n(9008),i=n(1576),c=n.n(i),l=n(4298),s=function(){return(0,r.BX)(r.HY,{children:[(0,r.tZ)(l.default,{strategy:"lazyOnload",src:"https://www.googletagmanager.com/gtag/js?id=".concat(c().analytics.googleAnalyticsId)}),(0,r.tZ)(l.default,{strategy:"lazyOnload",id:"ga-script",children:"\n            window.dataLayer = window.dataLayer || [];\n            function gtag(){dataLayer.push(arguments);}\n            gtag('js', new Date());\n            gtag('config', '".concat(c().analytics.googleAnalyticsId,"', {\n              page_path: window.location.pathname,\n            });\n        ")})]})};var u=function(){return(0,r.BX)(r.HY,{children:[(0,r.tZ)(l.default,{strategy:"lazyOnload","data-domain":c().analytics.plausibleDataDomain,src:"https://plausible.io/js/plausible.js"}),(0,r.tZ)(l.default,{strategy:"lazyOnload",id:"plausible-script",children:"\n            window.plausible = window.plausible || function() { (window.plausible.q = window.plausible.q || []).push(arguments) }\n        "})]})},f=function(){return(0,r.BX)(r.HY,{children:[(0,r.tZ)(l.default,{strategy:"lazyOnload",id:"sa-script",children:"\n            window.sa_event=window.sa_event||function(){var a=[].slice.call(arguments);window.sa_event.q?window.sa_event.q.push(a):window.sa_event.q=[a]};\n        "}),(0,r.tZ)(l.default,{strategy:"lazyOnload",src:"https://scripts.simpleanalyticscdn.com/latest.js"})]})},d=function(){return(0,r.tZ)(r.HY,{children:(0,r.tZ)(l.default,{async:!0,defer:!0,"data-website-id":c().analytics.umamiWebsiteId,src:"https://umami.example.com/umami.js"})})},h=function(){return(0,r.tZ)(r.HY,{children:(0,r.tZ)(l.default,{strategy:"lazyOnload",id:"posthog-script",children:'\n            !function(t,e){var o,n,p,r;e.__SV||(window.posthog=e,e._i=[],e.init=function(i,s,a){function g(t,e){var o=e.split(".");2==o.length&&(t=t[o[0]],e=o[1]),t[e]=function(){t.push([e].concat(Array.prototype.slice.call(arguments,0)))}}(p=t.createElement("script")).type="text/javascript",p.async=!0,p.src=s.api_host+"/static/array.js",(r=t.getElementsByTagName("script")[0]).parentNode.insertBefore(p,r);var u=e;for(void 0!==a?u=e[a]=[]:a="posthog",u.people=u.people||[],u.toString=function(t){var e="posthog";return"posthog"!==a&&(e+="."+a),t||(e+=" (stub)"),e},u.people.toString=function(){return u.toString(1)+".people (stub)"},o="capture identify alias people.set people.set_once set_config register register_once unregister opt_out_capturing has_opted_out_capturing opt_in_capturing reset isFeatureEnabled onFeatureFlags".split(" "),n=0;n<o.length;n++)g(u,o[n]);e._i.push([i,s,a])},e.__SV=1)}(document,window.posthog||[]);\n            posthog.init(\''.concat(c().analytics.posthogAnalyticsId,"',{api_host:'https://app.posthog.com'})\n        ")})})},m=function(){return(0,r.BX)(r.HY,{children:[c().analytics.plausibleDataDomain&&(0,r.tZ)(u,{}),c().analytics.simpleAnalytics&&(0,r.tZ)(f,{}),c().analytics.umamiWebsiteId&&(0,r.tZ)(d,{}),c().analytics.googleAnalyticsId&&(0,r.tZ)(s,{}),c().analytics.posthogAnalyticsId&&(0,r.tZ)(h,{})]})},p=[{href:"/",title:"Home"},{href:"/blog",title:"Blog"},{href:"/columns",title:"Column"},{href:"/projects",title:"Projects"},{href:"/about",title:"About"},{href:"/contact",title:"Contact"}],v=n(7233),g=n(890),y=n(4744);function w(){return(0,r.tZ)("footer",{children:(0,r.BX)("div",{className:"mt-16 flex flex-col items-center",children:[(0,r.BX)("div",{className:"mb-3 flex space-x-4",children:[(0,r.tZ)(y.Z,{kind:"mail",href:"mailto:".concat(c().email),size:"6"}),(0,r.tZ)(y.Z,{kind:"github",href:c().github,size:"6"}),(0,r.tZ)(y.Z,{kind:"juejin",href:c().juejin,size:"6"}),(0,r.tZ)(y.Z,{kind:"csdn",href:c().csdn,size:"6"})]}),(0,r.BX)("div",{className:"mb-2 flex space-x-2 text-sm text-gray-500 dark:text-gray-400",children:[(0,r.tZ)("div",{children:"\xa9 ".concat((new Date).getFullYear())}),(0,r.tZ)("div",{children:" \u2022 "}),(0,r.tZ)(v.Z,{href:"/",children:c().author})]})]})})}var b=n(1720),x=function(){var e=(0,b.useState)(!1),t=e[0],n=e[1],a=function(){n((function(e){return document.body.style.overflow=e?"auto":"hidden",!e}))};return(0,r.BX)("div",{className:"sm:hidden",children:[(0,r.tZ)("button",{type:"button",className:"ml-1 mr-1 h-8 w-8 rounded py-1","aria-label":"Toggle Menu",onClick:a,children:(0,r.tZ)("svg",{xmlns:"http://www.w3.org/2000/svg",viewBox:"0 0 20 20",fill:"currentColor",className:"text-gray-900 dark:text-gray-100",children:(0,r.tZ)("path",{fillRule:"evenodd",d:"M3 5a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zM3 10a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zM3 15a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z",clipRule:"evenodd"})})}),(0,r.BX)("div",{className:"fixed top-0 left-0 z-10 h-full w-full transform bg-gray-200 opacity-95 duration-300 ease-in-out dark:bg-gray-800 ".concat(t?"translate-x-0":"translate-x-full"),children:[(0,r.tZ)("div",{className:"flex justify-end",children:(0,r.tZ)("button",{type:"button",className:"mr-5 mt-11 h-8 w-8 rounded","aria-label":"Toggle Menu",onClick:a,children:(0,r.tZ)("svg",{xmlns:"http://www.w3.org/2000/svg",viewBox:"0 0 20 20",fill:"currentColor",className:"text-gray-900 dark:text-gray-100",children:(0,r.tZ)("path",{fillRule:"evenodd",d:"M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z",clipRule:"evenodd"})})})}),(0,r.tZ)("nav",{className:"fixed mt-8 h-full",children:p.map((function(e){return(0,r.tZ)("div",{className:"px-12 py-4",children:(0,r.tZ)(v.Z,{href:e.href,className:"text-2xl font-bold tracking-widest text-gray-900 dark:text-gray-100",onClick:a,children:e.title})},e.title)}))})]})]})},O=function(){var e=(0,b.useState)(!1),t=e[0],n=e[1],o=(0,a.F)(),i=o.theme,c=o.setTheme,l=o.resolvedTheme;return(0,b.useEffect)((function(){return n(!0)}),[]),(0,r.tZ)("button",{"aria-label":"Toggle Dark Mode",type:"button",className:"ml-1 mr-1 h-8 w-8 rounded p-1 sm:ml-4",onClick:function(){return c("dark"===i||"dark"===l?"light":"dark")},children:(0,r.tZ)("svg",{xmlns:"http://www.w3.org/2000/svg",viewBox:"0 0 20 20",fill:"currentColor",className:"text-gray-900 dark:text-gray-100",children:!t||"dark"!==i&&"dark"!==l?(0,r.tZ)("path",{d:"M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z"}):(0,r.tZ)("path",{fillRule:"evenodd",d:"M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z",clipRule:"evenodd"})})})},_=function(e){var t=e.children;return(0,r.tZ)(g.Z,{children:(0,r.BX)("div",{className:"flex h-screen flex-col justify-between",children:[(0,r.BX)("header",{className:"flex items-center justify-between py-10",children:[(0,r.tZ)("div",{children:(0,r.tZ)(v.Z,{href:"/","aria-label":c().headerTitle,children:(0,r.tZ)("div",{className:"flex items-center justify-between",children:"string"===typeof c().headerTitle?(0,r.tZ)("div",{className:"hidden h-6 text-2xl font-semibold sm:block",children:c().headerTitle}):c().headerTitle})})}),(0,r.BX)("div",{className:"flex items-center text-base leading-5",children:[(0,r.tZ)("div",{className:"hidden sm:block",children:p.map((function(e){return(0,r.tZ)(v.Z,{href:e.href,className:"p-1 font-medium text-gray-900 dark:text-gray-100 sm:p-4",children:e.title},e.title)}))}),(0,r.tZ)(O,{}),(0,r.tZ)(x,{})]})]}),(0,r.tZ)("main",{className:"mb-auto",children:t}),(0,r.tZ)(w,{})]})})},j=(n(1163),n(3454));function E(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function k(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{},r=Object.keys(n);"function"===typeof Object.getOwnPropertySymbols&&(r=r.concat(Object.getOwnPropertySymbols(n).filter((function(e){return Object.getOwnPropertyDescriptor(n,e).enumerable})))),r.forEach((function(t){E(e,t,n[t])}))}return e}j.env.SOCKET;function Z(e){var t=e.Component,n=e.pageProps;return(0,r.BX)(a.f,{attribute:"class",defaultTheme:c().theme,children:[(0,r.tZ)(o.default,{children:(0,r.tZ)("meta",{content:"width=device-width, initial-scale=1",name:"viewport"})}),false,(0,r.tZ)(m,{}),(0,r.tZ)(_,{children:(0,r.tZ)(t,k({},n))})]})}},8102:function(){},3941:function(){},7661:function(){},2604:function(){},7663:function(e){!function(){var t={162:function(e){var t,n,r=e.exports={};function a(){throw new Error("setTimeout has not been defined")}function o(){throw new Error("clearTimeout has not been defined")}function i(e){if(t===setTimeout)return setTimeout(e,0);if((t===a||!t)&&setTimeout)return t=setTimeout,setTimeout(e,0);try{return t(e,0)}catch(r){try{return t.call(null,e,0)}catch(r){return t.call(this,e,0)}}}!function(){try{t="function"===typeof setTimeout?setTimeout:a}catch(e){t=a}try{n="function"===typeof clearTimeout?clearTimeout:o}catch(e){n=o}}();var c,l=[],s=!1,u=-1;function f(){s&&c&&(s=!1,c.length?l=c.concat(l):u=-1,l.length&&d())}function d(){if(!s){var e=i(f);s=!0;for(var t=l.length;t;){for(c=l,l=[];++u<t;)c&&c[u].run();u=-1,t=l.length}c=null,s=!1,function(e){if(n===clearTimeout)return clearTimeout(e);if((n===o||!n)&&clearTimeout)return n=clearTimeout,clearTimeout(e);try{n(e)}catch(t){try{return n.call(null,e)}catch(t){return n.call(this,e)}}}(e)}}function h(e,t){this.fun=e,this.array=t}function m(){}r.nextTick=function(e){var t=new Array(arguments.length-1);if(arguments.length>1)for(var n=1;n<arguments.length;n++)t[n-1]=arguments[n];l.push(new h(e,t)),1!==l.length||s||i(d)},h.prototype.run=function(){this.fun.apply(null,this.array)},r.title="browser",r.browser=!0,r.env={},r.argv=[],r.version="",r.versions={},r.on=m,r.addListener=m,r.once=m,r.off=m,r.removeListener=m,r.removeAllListeners=m,r.emit=m,r.prependListener=m,r.prependOnceListener=m,r.listeners=function(e){return[]},r.binding=function(e){throw new Error("process.binding is not supported")},r.cwd=function(){return"/"},r.chdir=function(e){throw new Error("process.chdir is not supported")},r.umask=function(){return 0}}},n={};function r(e){var a=n[e];if(void 0!==a)return a.exports;var o=n[e]={exports:{}},i=!0;try{t[e](o,o.exports,r),i=!1}finally{i&&delete n[e]}return o.exports}r.ab="//";var a=r(162);e.exports=a}()},9008:function(e,t,n){e.exports=n(3121)},1664:function(e,t,n){e.exports=n(1551)},1163:function(e,t,n){e.exports=n(880)},4298:function(e,t,n){e.exports=n(3573)},6584:function(e,t,n){"use strict";n.r(t),n.d(t,{Fragment:function(){return r.HY},jsx:function(){return o},jsxDEV:function(){return o},jsxs:function(){return o}});var r=n(6400),a=0;function o(e,t,n,o,i){var c,l,s={};for(l in t)"ref"==l?c=t[l]:s[l]=t[l];var u={type:e,props:s,key:n,ref:c,__k:null,__:null,__b:0,__e:null,__d:void 0,__c:null,__h:null,constructor:void 0,__v:--a,__source:i,__self:o};if("function"==typeof e&&(c=e.defaultProps))for(l in c)void 0===s[l]&&(s[l]=c[l]);return r.YM.vnode&&r.YM.vnode(u),u}},7320:function(e,t,n){"use strict";n.d(t,{HY:function(){return r.Fragment},tZ:function(){return r.jsx},BX:function(){return r.jsxs}});n(1720);var r=n(6584)}},function(e){var t=function(t){return e(e.s=t)};e.O(0,[179],(function(){return t(1780),t(880)}));var n=e.O();_N_E=n}]);