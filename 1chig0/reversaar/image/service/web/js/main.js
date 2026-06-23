import { createApp, reactive } from 'vue'

const user = reactive(null);

const site = reactive({
    site: window.location.hash.substring(1),
    update_view(){
        this.site=window.location.hash.substring(1);
    }
});

const api = {
    async info() {
        const response = await fetch("/api/info");
        if(!response.ok){
            return null;
        }
        return await response.json();
    },
    async login(username, password){
        const response = await fetch("/api/login",{
            method: 'POST',
            body: JSON.stringify({username: username, password: password}),
            headers: {
                "Content-Type": "application/json",
            },
        });
        
        if(!response.ok) {
            throw `Could not login (${response.statusText})`;
        }
        return await response.json();
    },
    async reverse_text(text){
        console.log(text);
        const response = await fetch("/api/text/new",{
            method: 'POST',
            body: text,
            headers: {
                "Content-Type": "text/plain;charset=UTF-8",
            },
        });
        
        if(!response.ok) {
            throw `Error reversing text`;
        }
        return await response.json();
    },
    async reverse_array(array){
        console.log(array);
        const response = await fetch("/api/array/new",{
            method: 'POST',
            body: btoa(Array.from(array, (x) => String.fromCodePoint(x)).join("")),
            headers: {
                "Content-Type": "application/octet-stream",
                "Content-Transfer-Encoding": "base64",
            },
        });
        
        if(!response.ok) {
            throw `Error reversing array`;
        }
        return await response.json();
    }
    ,
    async reverse_audio(audio){
        console.log(audio);
        const filedata = await audio.arrayBuffer();
        console.log(filedata);
        const response = await fetch("/api/audio/new",{
            method: 'POST',
            body: filedata,
            headers: {
                "Content-Type": "application/octet-stream",
            },
        });
        
        if(!response.ok) {
            throw `Error reversing audio`;
        }
        return await response.json();
    }
}

function View(type, idx){
    const template = `#template-view-${type}`;
    const url = `/api/${type}/${idx-1}`;
    switch(type){
        case 'text':
            return {
                $template: template,
                url,
                content_text: null,
                get initialized(){
                    return this.content_text != null;
                },
                async mounted() {
                    const response = await fetch(this.url);
                    if(!response.ok) {
                        throw `Error loading ${this.url}`;
                    }
                    this.content_text = await response.text();
                }   
            }
            break;
        case 'array':
            return {
                $template: template,
                url,
                content_text: null,
                get initialized(){
                    return this.content_text != null;
                },
                async mounted() {
                    const response = await fetch(this.url);
                    if(!response.ok) {
                        throw `Error loading ${this.url}`;
                    }
                    this.content_text = JSON.stringify(Array.from(atob(await response.text()), (x) => x.codePointAt(0)));
                }
            }
            break;
        case 'audio':
            return {
                $template: template,
                url,
            }
            break;
        default:
            throw `Cannot find view for type ${type}`;
    }
}

function NewElement(type){
    const template = `#template-new-${type}`;
    switch(type){
        case 'text':
            return {
                $template: template,
                content_text: "",
                get valid(){
                    return true;
                },
                async send(){
                    const info = await api.reverse_text(this.content_text);
                    this.user.text = Math.max(this.user.text || 0, info.id+1);
                    this.open_idx = this.user.text;
                    this.content_text = "";
                }   
            }
            break;
        case 'array':
            return {
                $template: template,
                content_text: "",
                get content_array(){
                    try{
                        return JSON.parse(this.content_text);
                        
                    }catch(e){
                        return null;
                    }
                },
                get valid(){
                    return Array.isArray(this.content_array) && this.content_array.every(x => Number.isInteger(x) && x >= 0 && x<256);
                },
                async send(){
                    const info = await api.reverse_array(Array.from(this.content_array));
                    this.user.array = Math.max(this.user.array || 0, info.id+1);
                    this.open_idx = this.user.array;
                    this.content_text = "";
                }   
            }
            break;
        case 'audio':
            return {
                $template: template,
                selected_file: null,
                get valid(){
                    return true;
                },
                async send(){
                    const info = await api.reverse_audio(this.selected_file);
                    this.user.audio = Math.max(this.user.audio || 0, info.id+1);
                    this.open_idx = this.user.audio;
                    this.selected_file = null;
                }  
            }
            break;
        default:
            throw `Cannot find view for type ${type}`;
    }
}

function ListingElement(type, idx){
    return {
        View,
        idx,
        $template: '#template-listing-element',
        opened: false,
    }
}

function Listing(type, title) {
    return {
        ListingElement,
        NewElement,
        $template: '#template-listing',
        title: title,
        type: type,
        open_idx: 0,
        get count(){
            if(this.user != null && this.type in this.user){
                return this.user[this.type];
            }else{
                return 0;
            }
        }
    }
}

createApp({
    site,
    user,
    Listing,
    async fetch_info(){
        this.user = await api.info();
    },
    get logged_in(){
        return this.user != null
    },
    show_login:false,
    username: "",
    password: "",
    error: "",
    get username_valid(){
        this.username = this.username.replace(/\s+/gm, '');
        return this.username.length >= 1;
    },
    get password_valid(){
        return this.password.length >= 1;
    },
    async login(){
        if(this.username_valid && this.password_valid){
            try{
                this.user = await api.login(this.username, this.password);
                this.error = "";
                this.show_login = false;
                window.location.hash = '#profile';
            }catch (e){
                this.error = e;
            }
        }
    },
    logout(){
        document.cookie = "Session=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/api; SameSite=strict";
        window.location.hash = '#';
        this.user = null;
    }
}).mount('#main')

window.addEventListener("hashchange", (ev) => site.update_view());
