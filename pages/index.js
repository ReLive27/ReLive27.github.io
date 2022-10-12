import Link from '@/components/Link'
import { PageSEO } from '@/components/SEO'
import Tag from '@/components/Tag'
import siteMetadata from '@/data/siteMetadata'
import { getAllFilesFrontMatter } from '@/lib/mdx'
import formatDate from '@/lib/utils/formatDate'
import { RoughNotation } from 'react-rough-notation';


import NewsletterForm from '@/components/NewsletterForm'

const MAX_DISPLAY = 5

export async function getStaticProps() {
  const posts = await getAllFilesFrontMatter('blog')

  return { props: { posts } }
}

export default function Home({ posts }) {
  return (
    <>
      <PageSEO title={siteMetadata.title} description={siteMetadata.description} />
      <div className='fade-in banner flex flex-1 flex-col justify-center px-6 py-10 dark:text-white lg:px-10' style={{marginTop:"100px"}}>
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
    </>
  )
}
