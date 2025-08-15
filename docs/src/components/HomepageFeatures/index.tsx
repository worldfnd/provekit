import type {ReactNode} from 'react';
import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

type FeatureItem = {
  title: string;
  Svg: React.ComponentType<React.ComponentProps<'svg'>>;
  description: ReactNode;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'Mobile-First Zero-Knowledge',
    Svg: require('@site/static/img/undraw_docusaurus_mountain.svg').default,
    description: (
      <>
        ProveKit is specifically optimized for ARM64 architectures, delivering
        fast zero-knowledge proofs on mobile devices and resource-constrained environments.
      </>
    ),
  },
  {
    title: 'Developer-Friendly Toolchain',
    Svg: require('@site/static/img/undraw_docusaurus_tree.svg').default,
    description: (
      <>
        Write circuits in <strong>Noir</strong>, compile to efficient R1CS, and generate
        proofs with a single command. ProveKit handles the complexity so you can focus on your application.
      </>
    ),
  },
  {
    title: 'High-Performance Cryptography',
    Svg: require('@site/static/img/undraw_docusaurus_react.svg').default,
    description: (
      <>
        Hand-tuned ARM64 assembly, SIMD optimizations, and the custom Skyscraper hash
        function deliver industry-leading performance for zero-knowledge proof generation.
      </>
    ),
  },
];

function Feature({title, Svg, description}: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): ReactNode {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
