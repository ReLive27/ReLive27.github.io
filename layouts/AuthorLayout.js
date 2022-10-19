import Image from '@/components/Image'
import { PageSEO } from '@/components/SEO'
import { RoughNotation } from 'react-rough-notation'
import SocialIcon from '@/components/social-icons'
import siteMetadata from "@/data/siteMetadata";



export default function AuthorLayout({ children, frontMatter }) {
  const { name, avatar, occupation, company, email, twitter, linkedin, github } = frontMatter

  return (
    <>
      <PageSEO title={`About - ${name}`} description={`About me - ${name}`} />
      <div className="divide-y divide-gray-200 dark:divide-gray-700">
        <div className="space-y-2 pt-6 pb-8 md:space-y-5">
          <h1 className="text-3xl font-extrabold leading-9 tracking-tight text-gray-900 dark:text-gray-100 sm:text-4xl sm:leading-10 md:text-6xl md:leading-14">
            About
          </h1>
        </div>
        <div className="items-start space-y-2 xl:grid xl:grid-cols-3 xl:gap-x-8 xl:space-y-0">
          <div className="flex flex-col items-center pt-8">
            <Image
              src={avatar}
              alt="avatar"
              width="192px"
              height="192px"
              className="h-48 w-48 rounded-full"
            />
            <h3 className="pt-4 pb-2 text-2xl font-bold leading-8 tracking-tight">{name}</h3>
            <div className="text-gray-500 dark:text-gray-400">{occupation}</div>
            <div className="text-gray-500 dark:text-gray-400">{company}</div>
            <div className="flex space-x-3 pt-6">
              <SocialIcon kind="mail" href={`mailto:${siteMetadata.email}`} size="6" />
              <SocialIcon kind="github" href={siteMetadata.github} size="6" />
              <SocialIcon kind="juejin" href={siteMetadata.juejin} size="6" />
              <SocialIcon kind="csdn" href={siteMetadata.csdn} size="6" />
              <SocialIcon kind="jianshu" href={siteMetadata.jianshu} size="6" />
            </div>
          </div>
          <div className="prose max-w-none pt-8 pb-8 dark:prose-dark xl:col-span-2">
            {children}
            <p className='mt-8'>
              <a
                  className='!font-normal !text-black !no-underline dark:!text-white'
                  href='{resume}'
                  target='_blank'
                  rel='noreferrer'
              >
                <RoughNotation
                    show
                    type='box'
                    animationDelay={250}
                    animationDuration={2000}
                    strokeWidth={2}
                    color='#F5E1FF'
                >
                  Resume
                </RoughNotation>
              </a>
              <h2 className='mt-8 mb-4 text-2xl font-semibold dark:text-white'>
                Skills
              </h2>
              <div className='mb-2 flex flex-wrap'>
                 <span
                     className='mr-2 mb-2 rounded-sm px-2 py-1 text-xs font-medium text-white'
                     style={{background: '#00ADD8'}}
                     key='Java'
                 >Java</span>
                <span
                    className='mr-2 mb-2 rounded-sm px-2 py-1 text-xs font-medium text-white'
                    style={{background: '#68A063'}}
                    key='Spring'
                >Spring</span>
                <span
                    className='mr-2 mb-2 rounded-sm px-2 py-1 text-xs font-medium text-white'
                    style={{background: '#4285F4'}}
                    key='MySQL'
                >MySQL</span>
                <span
                    className='mr-2 mb-2 rounded-sm px-2 py-1 text-xs font-medium text-white'
                    style={{background: '#D82C20'}}
                    key='Redis'
                >Redis</span>
                <span
                    className='mr-2 mb-2 rounded-sm px-2 py-1 text-xs font-medium text-white'
                    style={{background: '#000000'}}
                    key='Kafka'
                >Kafka</span>
                <span
                    className='mr-2 mb-2 rounded-sm px-2 py-1 text-xs font-medium text-white'
                    style={{background: '#0DB7Ed'}}
                    key='Docker'
                >Docker</span>
                <span
                    className='mr-2 mb-2 rounded-sm px-2 py-1 text-xs font-medium text-white'
                    style={{background: '#26BE00'}}
                    key='Nginx'
                >Nginx</span>
                <span
                    className='mr-2 mb-2 rounded-sm px-2 py-1 text-xs font-medium text-white'
                    style={{background: '#FF9900'}}
                    key='Git'
                >Git</span>
              </div>
            </p>
          </div>
        </div>
      </div>
    </>
  )
}
