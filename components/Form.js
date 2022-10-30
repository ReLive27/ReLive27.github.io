import Link from "@/components/Link";

export function Header({title, subtitle, children}) {

    return (
        <div className='space-y-2 pt-6 pb-8 md:space-y-5'>
            <h1 className='text-3xl font-extrabold leading-9 tracking-tight text-gray-900 dark:text-gray-100 sm:text-4xl sm:leading-10 md:text-6xl md:leading-14'>
                {title}
            </h1>
            {subtitle && (
                <p className='text-lg leading-7 text-gray-500 dark:text-gray-400'>
                    {subtitle}
                </p>
            )}
            {children}
        </div>
    );
}

export function Elementor({title, subtitle, href}) {

    return (
        <div className="flex flex-row flex-wrap justify-between pb-4 pt-4 border-b-2 border-gray-300">
            <div className="flex justify-center items-center font-mono text-xl font-black text-primary-500 hover:text-primary-600 dark:hover:text-primary-400">
                <Link href='/spring-security-oauth2'><span className="inline-block align-middle">{title}</span></Link>
            </div>
            {/*<div className="w-1/3 p-1 rounded bg-gray-700">*/}
            {/*    <Link href='/about'><span className="font-normal text-2xl text-whit text-center">sss</span></Link>*/}
            {/*</div>*/}

        </div>
    );
}
