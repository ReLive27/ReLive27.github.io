import Link from '@/components/Link'
import {PageSEO} from '@/components/SEO'
import siteMetadata from '@/data/siteMetadata'
import {getAllFilesFrontMatter} from '@/lib/mdx'
import {RoughNotation} from 'react-rough-notation';
import SocialIcon from "@/components/social-icons";

const MAX_DISPLAY = 5

export async function getStaticProps() {
    const posts = await getAllFilesFrontMatter('blog')

    return {props: {posts}}
}

export default function Home({posts}) {
    return (
        <>
            <PageSEO title={siteMetadata.title} description={siteMetadata.description}/>
            <div className='fade-in banner flex flex-1 flex-row flex-wrap justify-between px-6 py-10 dark:text-white lg:px-10'>

                <div className="flex flex-col justify-center">
                    <h1 className='text-3xl font-bold dark:text-white lg:text-5xl'>
                        Hi, I am {siteMetadata.author}
                    </h1>
                    <p className='my-2 text-lg lg:my-4 lg:text-2xl'>
                        Intermediate Software Engineer
                    </p>
                    <p className='font-light lg:text-xl'>
                        Read more
                        <Link className='ml-2 mr-2 font-normal text-black' href='/about'>
                            <RoughNotation
                                show
                                type='highlight'
                                animationDelay={250}
                                animationDuration={2000}
                                color={'#F5E1FF'}
                            >
                                about me
                            </RoughNotation>
                        </Link>
                        or
                        <Link className='ml-2 font-normal text-black' href='/contact'>
                            <RoughNotation
                                show
                                type='highlight'
                                animationDelay={250}
                                animationDuration={2000}
                                color={'#CAF0F8'}
                            >
                                contact me
                            </RoughNotation>
                        </Link>
                    </p>
                </div>


                <div className="flex justify-start">
                    <div className="grid grid-cols-1 grid-rows-3 gap-8 py-12">

                        <div className="grid gap-8 items-start my-2">
                            <div className="relative group">
                                <div
                                    className="absolute -inset-0.5 bg-gradient-to-r from-green-600 to-amber-500 rounded-lg blur opacity-25 group-hover:opacity-100 transition duration-1000 group-hover:duration-200 animate-tilt"></div>
                                <Link href="/blog">
                                    <a><span
                                        className="relative flex items-center divide-x divide-gray-600 rounded-lg bg-white px-7 py-4 leading-none dark:bg-black"><span
                                        className="flex items-center space-x-5">
                                        <SocialIcon kind="educate" href="/blog" size="6"/>
                                        <span
                                            className="pr-6 text-gray-900 dark:text-gray-100">Read my article</span></span><span
                                        className="pl-6 text-primary-400 transition duration-200 group-hover:text-gray-900 dark:group-hover:text-gray-100">Blog&nbsp;→</span></span></a>
                                </Link>
                            </div>
                        </div>
                        <div className="my-2 grid items-start gap-8">
                            <div className="group relative">
                                <div
                                    className="animate-tilt absolute -inset-0.5 rounded-lg bg-gradient-to-r from-pink-600 to-purple-600 opacity-50 blur transition duration-1000 group-hover:opacity-100 group-hover:duration-200"></div>
                                <Link href="/projects">
                                    <a><span
                                        className="relative flex items-center divide-x divide-gray-600 rounded-lg bg-white px-7 py-4 leading-none dark:bg-black"><span
                                        className="flex items-center space-x-5">
                                         <SocialIcon kind="chemistry" href="/projects" size="6"/>
                                        <span
                                            className="pr-6 text-gray-900 dark:text-gray-100">What I built</span></span><span
                                        className="pl-6 text-amber-400 transition duration-200 group-hover:text-gray-900 dark:group-hover:text-gray-100">Projects&nbsp;→</span></span></a>
                                </Link>
                            </div>
                        </div>
                        <div className="my-2 grid items-start gap-8">
                            <div className="group relative">
                                <div
                                    className="animate-tilt absolute -inset-0.5 rounded-lg bg-gradient-to-r from-fuchsia-600 to-emerald-600 opacity-50 blur transition duration-1000 group-hover:opacity-100 group-hover:duration-200"></div>
                                <Link href="/about">
                                    <a><span
                                        className="relative flex items-center divide-x divide-gray-600 rounded-lg bg-white px-7 py-4 leading-none dark:bg-black"><span
                                        className="flex items-center space-x-5">
                                        <SocialIcon kind="book" href="/about" size="6"/>
                                        <span
                                            className="pr-6 text-gray-900 dark:text-gray-100">About my introduction</span></span><span
                                        className="pl-6 text-indigo-400 transition duration-200 group-hover:text-gray-900 dark:group-hover:text-gray-100">About&nbsp;→</span></span></a>
                                </Link>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

        </>
    )
}
